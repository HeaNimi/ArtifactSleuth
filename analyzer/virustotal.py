"""
VirusTotal API integration module.
Supports hash lookups with configurable rate limiting.
"""

import time
import hashlib
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from collections import deque

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class VTResult:
    """VirusTotal lookup result."""
    detected: bool
    detection_ratio: str  # e.g., "5/72"
    positives: int
    total: int
    permalink: str
    scan_date: Optional[str] = None
    error: Optional[str] = None


class RateLimiter:
    """
    Rate limiter that tracks request timestamps.
    Ensures we don't exceed the specified rate.
    """
    
    def __init__(self, max_requests: int, time_window: float = 60.0):
        """
        Args:
            max_requests: Maximum requests allowed per time window
            time_window: Time window in seconds (default 60 = 1 minute)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_times = deque()
    
    def wait_if_needed(self) -> float:
        """
        Wait if we've exceeded the rate limit.
        Returns the time waited in seconds.
        """
        now = time.time()
        
        # Remove old timestamps outside the window
        while self.request_times and now - self.request_times[0] > self.time_window:
            self.request_times.popleft()
        
        # If we're at the limit, wait
        wait_time = 0.0
        if len(self.request_times) >= self.max_requests:
            oldest = self.request_times[0]
            wait_time = self.time_window - (now - oldest) + 0.1  # Add small buffer
            if wait_time > 0:
                time.sleep(wait_time)
        
        # Record this request
        self.request_times.append(time.time())
        return wait_time
    
    def get_remaining(self) -> int:
        """Get remaining requests in the current window."""
        now = time.time()
        while self.request_times and now - self.request_times[0] > self.time_window:
            self.request_times.popleft()
        return max(0, self.max_requests - len(self.request_times))


class VirusTotalClient:
    """
    VirusTotal API client with rate limiting.
    
    Usage:
        client = VirusTotalClient(api_key="YOUR_KEY", rate_limit=4)
        result = client.lookup_hash(sha256_hash)
    """
    
    API_URL = "https://www.virustotal.com/vtapi/v2/file/report"
    
    def __init__(
        self, 
        api_key: str, 
        rate_limit: int = 4,
        timeout: int = 30
    ):
        """
        Initialize VirusTotal client.
        
        Args:
            api_key: VirusTotal API key
            rate_limit: Maximum lookups per minute (4 for free, 500 for premium)
            timeout: Request timeout in seconds
        """
        if not HAS_REQUESTS:
            raise ImportError("requests library required. Install with: pip install requests")
        
        self.api_key = api_key
        self.rate_limiter = RateLimiter(max_requests=rate_limit, time_window=60.0)
        self.timeout = timeout
        self._cache: Dict[str, VTResult] = {}
        self.total_lookups = 0
        self.cache_hits = 0
    
    def lookup_hash(self, file_hash: str) -> VTResult:
        """
        Look up a file hash on VirusTotal.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
        
        Returns:
            VTResult with detection information
        """
        # Normalize hash
        file_hash = file_hash.lower().strip()
        
        # Check cache
        if file_hash in self._cache:
            self.cache_hits += 1
            return self._cache[file_hash]
        
        # Wait for rate limit
        self.rate_limiter.wait_if_needed()
        self.total_lookups += 1
        
        try:
            response = requests.get(
                self.API_URL,
                params={
                    'apikey': self.api_key,
                    'resource': file_hash
                },
                timeout=self.timeout
            )
            
            if response.status_code == 204:
                # Rate limit exceeded (shouldn't happen with our limiter)
                result = VTResult(
                    detected=False,
                    detection_ratio="0/0",
                    positives=0,
                    total=0,
                    permalink="",
                    error="Rate limit exceeded"
                )
            elif response.status_code == 403:
                result = VTResult(
                    detected=False,
                    detection_ratio="0/0",
                    positives=0,
                    total=0,
                    permalink="",
                    error="Invalid API key"
                )
            elif response.status_code != 200:
                result = VTResult(
                    detected=False,
                    detection_ratio="0/0",
                    positives=0,
                    total=0,
                    permalink="",
                    error=f"HTTP {response.status_code}"
                )
            else:
                data = response.json()
                
                if data.get('response_code') == 0:
                    # Hash not found in VT database
                    result = VTResult(
                        detected=False,
                        detection_ratio="Not found",
                        positives=0,
                        total=0,
                        permalink=f"https://www.virustotal.com/gui/file/{file_hash}"
                    )
                else:
                    positives = data.get('positives', 0)
                    total = data.get('total', 0)
                    result = VTResult(
                        detected=positives > 0,
                        detection_ratio=f"{positives}/{total}",
                        positives=positives,
                        total=total,
                        permalink=data.get('permalink', ''),
                        scan_date=data.get('scan_date')
                    )
        
        except requests.exceptions.Timeout:
            result = VTResult(
                detected=False,
                detection_ratio="0/0",
                positives=0,
                total=0,
                permalink="",
                error="Request timeout"
            )
        except requests.exceptions.RequestException as e:
            result = VTResult(
                detected=False,
                detection_ratio="0/0",
                positives=0,
                total=0,
                permalink="",
                error=str(e)
            )
        
        # Cache the result
        self._cache[file_hash] = result
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get lookup statistics."""
        return {
            'total_lookups': self.total_lookups,
            'cache_hits': self.cache_hits,
            'cache_size': len(self._cache),
            'remaining_in_window': self.rate_limiter.get_remaining()
        }


def lookup_files_virustotal(
    files: list,
    api_key: str,
    rate_limit: int = 4,
    progress_callback=None
) -> None:
    """
    Look up file hashes on VirusTotal and update FileInfo objects in place.
    
    Args:
        files: List of FileInfo objects with sha256 hashes
        api_key: VirusTotal API key
        rate_limit: Lookups per minute (4 free, 500 premium)
        progress_callback: Optional callback(current, total, message)
    """
    client = VirusTotalClient(api_key=api_key, rate_limit=rate_limit)
    
    # Only lookup files with SHA256 hashes
    lookup_files = [f for f in files if f.sha256 and not f.is_directory]
    total = len(lookup_files)
    
    for i, file_info in enumerate(lookup_files):
        if progress_callback:
            remaining = client.rate_limiter.get_remaining()
            progress_callback(
                i + 1, 
                total, 
                f"Looking up {file_info.name} (Rate: {remaining}/min remaining)"
            )
        
        result = client.lookup_hash(file_info.sha256)
        
        file_info.vt_detected = result.detected
        file_info.vt_detection_ratio = result.detection_ratio
        file_info.vt_link = result.permalink
        file_info.vt_error = result.error
    
    return client.get_stats()

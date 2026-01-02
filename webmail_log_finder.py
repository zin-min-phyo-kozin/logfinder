#!/usr/bin/env python3
"""
Enhanced Webmail Log Finder with Threaded Scanning Implementation
Efficiently scans webmail logs using multi-threaded processing for improved performance.
"""

import os
import re
import sys
import json
import queue
import logging
import argparse
import threading
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


@dataclass
class LogEntry:
    """Represents a parsed webmail log entry."""
    timestamp: str
    level: str
    message: str
    source_file: str
    line_number: int
    email: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert log entry to dictionary."""
        return asdict(self)


class WebmailLogParser:
    """Parses webmail log files with pattern matching."""
    
    # Common webmail log patterns
    LOG_PATTERNS = {
        'timestamp': r'\[(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\]',
        'level': r'\[(?P<level>INFO|DEBUG|ERROR|WARNING|CRITICAL)\]',
        'email': r'(?P<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        'user': r'user[=:\s]+(?P<user>[a-zA-Z0-9_-]+)',
        'action': r'(?P<action>LOGIN|LOGOUT|SEND|RECEIVE|DELETE|CREATE|UPDATE)',
        'status': r'(?P<status>SUCCESS|FAILED|ERROR|PENDING)',
        'ip_address': r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    }
    
    def __init__(self):
        """Initialize the parser with compiled regex patterns."""
        self.compiled_patterns = {
            key: re.compile(pattern) for key, pattern in self.LOG_PATTERNS.items()
        }
    
    def parse_line(self, line: str, file_path: str, line_number: int) -> Optional[LogEntry]:
        """
        Parse a single log line and extract relevant information.
        
        Args:
            line: The log line to parse
            file_path: Path to the source file
            line_number: Line number in the file
            
        Returns:
            LogEntry object or None if parsing fails
        """
        if not line.strip():
            return None
        
        try:
            timestamp = self._extract_group(line, 'timestamp')
            level = self._extract_group(line, 'level', 'INFO')
            email = self._extract_group(line, 'email')
            user = self._extract_group(line, 'user')
            action = self._extract_group(line, 'action')
            status = self._extract_group(line, 'status')
            
            return LogEntry(
                timestamp=timestamp or datetime.now().isoformat(),
                level=level,
                message=line.strip(),
                source_file=file_path,
                line_number=line_number,
                email=email,
                user=user,
                action=action,
                status=status
            )
        except Exception as e:
            logging.warning(f"Failed to parse line {line_number} in {file_path}: {e}")
            return None
    
    def _extract_group(self, line: str, pattern_key: str, default: str = None) -> Optional[str]:
        """
        Extract a matched group from the line.
        
        Args:
            line: The line to search
            pattern_key: The pattern key to use
            default: Default value if no match found
            
        Returns:
            Matched value or default
        """
        pattern = self.compiled_patterns.get(pattern_key)
        if pattern:
            match = pattern.search(line)
            if match:
                return match.group(pattern_key)
        return default


class ThreadedLogScanner:
    """Scans log files using multiple threads for improved performance."""
    
    def __init__(self, max_workers: int = 4, chunk_size: int = 10000):
        """
        Initialize the threaded scanner.
        
        Args:
            max_workers: Maximum number of worker threads
            chunk_size: Number of lines to process before updating results
        """
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.parser = WebmailLogParser()
        self.results = []
        self.results_lock = threading.Lock()
        self.stats = {
            'files_processed': 0,
            'lines_parsed': 0,
            'entries_found': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }
        self.stats_lock = threading.Lock()
        
        # Setup logging
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def scan_directory(self, directory: str, pattern: str = "*.log") -> List[LogEntry]:
        """
        Scan a directory for log files using multiple threads.
        
        Args:
            directory: Directory path to scan
            pattern: File pattern to match (default: *.log)
            
        Returns:
            List of parsed log entries
        """
        self.stats['start_time'] = datetime.now()
        self.results = []
        
        log_files = self._find_log_files(directory, pattern)
        
        if not log_files:
            self.logger.warning(f"No log files found in {directory} matching pattern {pattern}")
            return []
        
        self.logger.info(f"Found {len(log_files)} log files to process")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_file, file_path): file_path
                for file_path in log_files
            }
            
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    entries = future.result()
                    with self.results_lock:
                        self.results.extend(entries)
                    self.logger.debug(f"Processed {len(entries)} entries from {file_path}")
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {e}")
                    with self.stats_lock:
                        self.stats['errors'] += 1
        
        self.stats['end_time'] = datetime.now()
        self.logger.info(f"Scan complete. Found {len(self.results)} log entries")
        return self.results
    
    def _find_log_files(self, directory: str, pattern: str) -> List[str]:
        """
        Find all log files matching the pattern in the directory.
        
        Args:
            directory: Directory to search
            pattern: File pattern to match
            
        Returns:
            List of file paths
        """
        try:
            path = Path(directory)
            return [str(f) for f in path.rglob(pattern) if f.is_file()]
        except Exception as e:
            self.logger.error(f"Error finding log files: {e}")
            return []
    
    def _scan_file(self, file_path: str) -> List[LogEntry]:
        """
        Scan a single log file for entries.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of parsed log entries from the file
        """
        entries = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    entry = self.parser.parse_line(line, file_path, line_number)
                    if entry:
                        entries.append(entry)
            
            with self.stats_lock:
                self.stats['files_processed'] += 1
                self.stats['lines_parsed'] += line_number
                self.stats['entries_found'] += len(entries)
        
        except IOError as e:
            self.logger.error(f"Failed to read file {file_path}: {e}")
            with self.stats_lock:
                self.stats['errors'] += 1
        
        return entries
    
    def filter_results(self, email: Optional[str] = None, 
                      action: Optional[str] = None,
                      status: Optional[str] = None) -> List[LogEntry]:
        """
        Filter results based on criteria.
        
        Args:
            email: Filter by email address
            action: Filter by action type
            status: Filter by status
            
        Returns:
            Filtered list of log entries
        """
        filtered = self.results
        
        if email:
            filtered = [e for e in filtered if e.email and email.lower() in e.email.lower()]
        
        if action:
            filtered = [e for e in filtered if e.action and e.action.upper() == action.upper()]
        
        if status:
            filtered = [e for e in filtered if e.status and e.status.upper() == status.upper()]
        
        return filtered
    
    def get_statistics(self) -> Dict:
        """
        Get scanning statistics.
        
        Returns:
            Dictionary with scanning statistics
        """
        stats = self.stats.copy()
        if stats['start_time'] and stats['end_time']:
            duration = (stats['end_time'] - stats['start_time']).total_seconds()
            stats['duration_seconds'] = duration
            stats['entries_per_second'] = (
                stats['entries_found'] / duration if duration > 0 else 0
            )
        return stats
    
    def export_results(self, output_file: str, format: str = 'json') -> None:
        """
        Export results to a file.
        
        Args:
            output_file: Path to output file
            format: Output format ('json' or 'csv')
        """
        try:
            if format.lower() == 'json':
                self._export_json(output_file)
            elif format.lower() == 'csv':
                self._export_csv(output_file)
            else:
                self.logger.error(f"Unsupported format: {format}")
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
    
    def _export_json(self, output_file: str) -> None:
        """Export results as JSON."""
        data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'entries': [entry.to_dict() for entry in self.results]
        }
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        self.logger.info(f"Results exported to {output_file}")
    
    def _export_csv(self, output_file: str) -> None:
        """Export results as CSV."""
        import csv
        try:
            with open(output_file, 'w', newline='') as f:
                if self.results:
                    fieldnames = self.results[0].to_dict().keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for entry in self.results:
                        writer.writerow(entry.to_dict())
            self.logger.info(f"Results exported to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to export CSV: {e}")
    
    def generate_report(self) -> Dict:
        """
        Generate a comprehensive report of findings.
        
        Returns:
            Dictionary containing report data
        """
        report = {
            'summary': self.get_statistics(),
            'emails_found': list(set(e.email for e in self.results if e.email)),
            'users_found': list(set(e.user for e in self.results if e.user)),
            'actions_summary': self._count_actions(),
            'status_summary': self._count_status(),
            'files_processed': list(set(e.source_file for e in self.results)),
        }
        return report
    
    def _count_actions(self) -> Dict[str, int]:
        """Count occurrences of each action."""
        counts = defaultdict(int)
        for entry in self.results:
            if entry.action:
                counts[entry.action] += 1
        return dict(counts)
    
    def _count_status(self) -> Dict[str, int]:
        """Count occurrences of each status."""
        counts = defaultdict(int)
        for entry in self.results:
            if entry.status:
                counts[entry.status] += 1
        return dict(counts)


def main():
    """Main entry point for the webmail log finder."""
    parser = argparse.ArgumentParser(
        description='Enhanced Webmail Log Finder with Threaded Scanning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s /var/log/webmail --pattern "*.log"
  %(prog)s /var/log/webmail --email user@example.com
  %(prog)s /var/log/webmail --action LOGIN --output results.json
  %(prog)s /var/log/webmail --workers 8 --output results.csv --format csv
        '''
    )
    
    parser.add_argument('directory', help='Directory containing log files')
    parser.add_argument('--pattern', default='*.log', help='File pattern to match (default: *.log)')
    parser.add_argument('--email', help='Filter by email address')
    parser.add_argument('--action', help='Filter by action (LOGIN, LOGOUT, SEND, etc.)')
    parser.add_argument('--status', help='Filter by status (SUCCESS, FAILED, etc.)')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker threads (default: 4)')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('--report', action='store_true', help='Generate a summary report')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create scanner and run
    scanner = ThreadedLogScanner(max_workers=args.workers)
    
    print(f"\n{'='*60}")
    print("Webmail Log Finder - Threaded Scanning")
    print(f"{'='*60}\n")
    
    # Scan directory
    results = scanner.scan_directory(args.directory, args.pattern)
    
    # Apply filters if specified
    if args.email or args.action or args.status:
        results = scanner.filter_results(
            email=args.email,
            action=args.action,
            status=args.status
        )
        print(f"\nFilters applied. Found {len(results)} matching entries.\n")
    
    # Export results if requested
    if args.output:
        scanner.export_results(args.output, args.format)
    
    # Generate report if requested
    if args.report:
        report = scanner.generate_report()
        print("\n" + "="*60)
        print("SCAN REPORT")
        print("="*60)
        print(json.dumps(report, indent=2, default=str))
    
    # Print statistics
    stats = scanner.get_statistics()
    print(f"\n{'='*60}")
    print("STATISTICS")
    print(f"{'='*60}")
    print(f"Files Processed: {stats['files_processed']}")
    print(f"Lines Parsed: {stats['lines_parsed']}")
    print(f"Entries Found: {stats['entries_found']}")
    print(f"Errors: {stats['errors']}")
    if 'duration_seconds' in stats:
        print(f"Duration: {stats['duration_seconds']:.2f} seconds")
        print(f"Entries/Second: {stats['entries_per_second']:.2f}")
    print(f"{'='*60}\n")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

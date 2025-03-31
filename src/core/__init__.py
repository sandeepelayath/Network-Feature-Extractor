"""
Core modules for the Network Feature Extractor.

Thread Safety and Lock Ordering:
When acquiring multiple locks across components, always follow this order
to prevent deadlocks:

1. Config lock (highest priority)
2. FlowTracker lock
3. CSVWriter lock (lowest priority)

Example:
```python
with config._config_lock:  # 1. Config lock first
    # Config operations
    with flow_tracker.flow_lock:  # 2. FlowTracker lock second
        # Flow operations
        with csv_writer.file_lock:  # 3. CSVWriter lock last
            # File operations
```

Never acquire locks in a different order to avoid deadlocks.
"""

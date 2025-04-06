"""
Network Feature Extractor package.
"""

__version__ = '0.1.0'

def get_config():
    from .core.config import Config
    return Config

def get_packet_capture():
    from .core.packet_capture import PacketCapture
    return PacketCapture

def get_flow_tracker():
    from .core.flow_tracker import FlowTracker
    return FlowTracker

def get_feature_extractors():
    from .feature_extraction import BaseFeatureExtractor, FeatureExtractorRegistry
    return BaseFeatureExtractor, FeatureExtractorRegistry

def get_csv_writer():
    from .output.csv_writer import CSVWriter
    return CSVWriter

def get_prometheus_exporter():
    from .monitoring.prometheus_exporter import PrometheusExporter
    return PrometheusExporter

def get_logger():
    from .logging.logger import Logger
    return Logger

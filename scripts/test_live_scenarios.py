"""
Live Scenario Test against running FastAPI server
Tests Scenario A (Benign), Scenario B (Suspicious), and Scenario C (Malicious).
"""
import urllib.request
import json

scenarios = {
    'Scenario A (Benign)': {
        'case_id': 'CASE-DEMO-A',
        'feature_vector': {
            'process_count': 18,
            'suspicious_process_count': 0,
            'temp_path_process_count': 0,
            'connection_count': 5,
            'external_connection_count': 1,
            'suspicious_port_count': 0,
            'persistence_count': 4,
            'suspicious_persistence_count': 0,
            'file_count': 10,
            'pe_anomaly_count': 0,
            'suspicious_file_count': 0,
            'ioc_count': 0,
            'malicious_ioc_count': 0,
            'suspicious_ioc_count': 0,
            'ip_ioc_count': 0,
            'hash_ioc_count': 0,
            'timeline_event_count': 30,
            'security_event_count': 0,
            'cti_match_count': 0,
            'mitre_technique_count': 0,
            'tamper_event_count': 0
        }
    },
    'Scenario B (Suspicious)': {
        'case_id': 'CASE-DEMO-B',
        'feature_vector': {
            'process_count': 24,
            'suspicious_process_count': 1,
            'temp_path_process_count': 1,
            'connection_count': 12,
            'external_connection_count': 4,
            'suspicious_port_count': 1,
            'persistence_count': 6,
            'suspicious_persistence_count': 1,
            'file_count': 18,
            'pe_anomaly_count': 0,
            'suspicious_file_count': 1,
            'ioc_count': 2,
            'malicious_ioc_count': 0,
            'suspicious_ioc_count': 2,
            'ip_ioc_count': 1,
            'hash_ioc_count': 1,
            'timeline_event_count': 45,
            'security_event_count': 1,
            'cti_match_count': 0,
            'mitre_technique_count': 2,
            'tamper_event_count': 0
        }
    },
    'Scenario C (Malicious)': {
        'case_id': 'CASE-DEMO-C',
        'feature_vector': {
            'process_count': 32,
            'suspicious_process_count': 4,
            'temp_path_process_count': 3,
            'connection_count': 28,
            'external_connection_count': 15,
            'suspicious_port_count': 3,
            'persistence_count': 10,
            'suspicious_persistence_count': 3,
            'file_count': 45,
            'pe_anomaly_count': 2,
            'suspicious_file_count': 4,
            'ioc_count': 6,
            'malicious_ioc_count': 4,
            'suspicious_ioc_count': 2,
            'ip_ioc_count': 3,
            'hash_ioc_count': 2,
            'timeline_event_count': 90,
            'security_event_count': 3,
            'cti_match_count': 2,
            'mitre_technique_count': 5,
            'tamper_event_count': 1
        }
    }
}

for name, payload in scenarios.items():
    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/ml/predict',
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print('=' * 60)
    print(name)
    print('Classification: ', res['classification'])
    print('Threat Score:   ', res['threat_score'])
    print('Confidence:     ', res['confidence'])
    print('Prediction Hash:', res['prediction_hash'])
    print('Top Factors:')
    for f in res['top_factors'][:3]:
        print(f"  - [{f['feature']}] Impact: {f['impact_score']:.4f} -> {f['description']}")

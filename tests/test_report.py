from mcpverity.report import scan_to_json, scan_to_sarif


def test_sarif_export_shape(scan_files):
    scan = scan_files([{"path": "server.py", "content": 'API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"\n'}])
    sarif = scan_to_sarif(scan)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "MCPVerity"
    results = sarif["runs"][0]["results"]
    assert len(results) > 0
    for res in results:
        assert "confidence" in res["properties"]
        assert 0.0 <= res["properties"]["confidence"] <= 1.0


def test_json_export_shape(scan_files):
    scan = scan_files([{"path": "server.py", "content": 'API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"\n'}])
    data = scan_to_json(scan)
    assert data["id"] == scan.id
    assert "findings" in data
    assert data["findings"][0]["rule_id"]

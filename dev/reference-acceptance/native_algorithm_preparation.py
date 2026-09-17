"""Validate existing native-import receipts; never infer import from a metadata fetch."""
import hashlib
import json


def verify(folder, variant):
    path = folder / variant
    imported = json.loads((path / 'import.json').read_text())
    digest = hashlib.sha256((path / 'fixture.xml').read_bytes()).hexdigest()
    assert imported['status'] == 'success'
    if imported.get('import_path') == 'native-parser-cli':
        assert imported['product'] == 'simplesamlphp'
        assert imported['fixture_sha256'] == digest
        assert imported['restored'] and imported['configuration_read_back']
        assert hashlib.sha256((path / 'parser-output.json').read_bytes()).hexdigest() == imported['parser_output_sha256']
    else:
        assert imported['fixture']['sha256'] == digest
        assert imported['import']['save_clicked']
        assert imported['import']['ui_status'] == 'client-settings-page'
        assert imported['import']['read_back']['client_id'] == imported['fixture']['entity_id']
        database_id = imported['client']['database_id']
        assert database_id and imported['import']['final_url'].endswith('/clients/' + database_id + '/settings')
        assert imported['cleanup']['read_back_absent']
    flow = json.loads((path / 'flow.json').read_text())
    assert flow['variant'] == variant and flow['correlated_success']
    assert flow['after_index'] == flow['before_index'] + 1
    return digest

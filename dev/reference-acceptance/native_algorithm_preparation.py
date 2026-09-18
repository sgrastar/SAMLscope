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
        if imported.get('restoration_scope') == 'batch-finally':
            restoration = json.loads((folder / 'restoration.json').read_text())
            assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
            assert not imported['restoration_pending']

        assert hashlib.sha256((path / 'parser-output.json').read_bytes()).hexdigest() == imported['parser_output_sha256']
    elif imported.get('import_path') == 'native-filesystem-provider':
        assert imported['product'] == 'shibboleth'
        assert imported['fixture_sha256'] == digest
        assert imported['configuration_read_back'] and imported['provider_reloaded'] and imported['restored']
        restoration = json.loads((folder / 'restoration.json').read_text())
        assert restoration['restored'] and restoration['temporary_file_removed']
        assert restoration['original_sha256'] == restoration['final_sha256']
        assert hashlib.sha256((folder / 'original-providers.xml').read_bytes()).hexdigest() == restoration['original_sha256']
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

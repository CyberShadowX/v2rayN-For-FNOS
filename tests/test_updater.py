import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from runtime import updater


class DownloadIntegrityTests(unittest.TestCase):
    def asset(self,body):
        return {'size':len(body),'sha256':hashlib.sha256(body).hexdigest(),'browser_download_url':'https://github.com/2dust/v2rayN/releases/download/test/file.zip'}

    def test_exact_bytes_and_hash_required(self):
        good=b'verified release bytes'
        for received in (b'wrong release bytes!',good[:-1],good+b'x'):
            with self.subTest(received=received),tempfile.TemporaryDirectory() as tmp:
                with patch.object(updater,'open_url',return_value=io.BytesIO(received)):
                    with self.assertRaises(ValueError):updater.download(self.asset(good),Path(tmp)/'asset')

    def test_verified_download(self):
        body=b'official release'
        with tempfile.TemporaryDirectory() as tmp,patch.object(updater,'open_url',return_value=io.BytesIO(body)):
            path=Path(tmp)/'asset';updater.download(self.asset(body),path)
            self.assertEqual(path.read_bytes(),body)

    def test_asset_url_cannot_be_arbitrary_host(self):
        for url in ('http://github.com/file','https://github.com.evil/file','file:///etc/passwd','https://api.github.com.evil/repos/x'):
            with self.subTest(url=url),self.assertRaises(ValueError):updater.open_url(url)

    def test_failed_staging_is_removed(self):
        class Adapter:
            def extract(self,*args):raise ValueError('bad archive')
        asset={'version':'1.0.0','name':'a.zip','size':1,'sha256':'0'*64}
        with tempfile.TemporaryDirectory() as tmp,patch.object(updater,'latest',return_value=asset),patch.object(updater,'download'):
            with self.assertRaises(ValueError):updater.stage(Adapter(),Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()),[])


if __name__=='__main__':unittest.main()

from unittest import mock
from urllib import request
from urllib import response
import builtins
import io
import tarfile
import unittest
import urllib

import hikibuta

class HikibutaTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self._url = 'https://archive/url'
    self._outpath = '/unittest/tmp'
    self._whitelist = []
    self._blacklist = []

  @mock.patch.object(tarfile, 'open')
  @mock.patch.object(request, 'urlopen')
  @mock.patch.object(builtins, 'open')
  def test_default(self, mock_open, mock_urlopen, mock_tar_open):
    out, mock_tar = self._prepare_mocks(mock_open, mock_urlopen, mock_tar_open)
    buta = hikibuta.Hikibuta(
        self._url,
        self._outpath,
        self._whitelist,
        self._blacklist)
    buta.fetch_rules()

    mock_tar_open.assert_called_once_with(fileobj=mock.ANY)
    self.assertTrue(mock_tar.getmembers.called)

    self.assertTrue(mock_urlopen.called)
    self.assertTrue(mock_tar_open.called)
    self.assertTrue(mock_open.called)

    # Test that we have what we expect in the output rules file.
    # First line is a comment, stays unchanged.
    self.assertTrue(
        mock.call(
            '# hey that\'s a nice file you have here\n'
        ) in out.write.call_args_list,
        out.write.call_args_list)
    # Second line is a rule and is commented too.
    self.assertTrue(
        mock.call(
            '# alert udp $HOME_NET any -> $EXTERNAL_NET 53 '
            '(msg:"foobar" sid:0;)') in out.write.call_args_list,
        out.write.call_args_list)
    # Now test a line that should be written.
    self.assertTrue(
        mock.call(
            'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:2;)'
        ) in out.write.call_args_list,
        out.write.call_args_list)
    # We also keep the empty newlines as is.
    self.assertTrue(
        mock.call('\n') in out.write.call_args_list,
        out.write.call_args_list)

  @staticmethod
  def _prepare_mocks(mock_open, mock_urlopen, mock_tar_open):
    mock_urlopen.return_value = response.addinfourl(
          io.BytesIO('some raw tar.gz'.encode('utf-8')),
          {'content-encoding': 'utf-8'}, '', 200)

    mock_tar = mock.create_autospec(tarfile.TarFile)
    mock_tar_open.return_value.__enter__.return_value = mock_tar

    # First file, not a file...
    tar_info_not_file = mock.create_autospec(tarfile.TarInfo)
    tar_info_not_file.isfile.return_value = False

    # Second file is dangerous.
    tar_info_dot_dot = mock.create_autospec(tarfile.TarInfo)
    tar_info_dot_dot.isfile.return_value = True
    type(tar_info_dot_dot).name = '../../etc/shadow'

    # Third file is dangerous too.
    tar_info_slash = mock.create_autospec(tarfile.TarInfo)
    tar_info_slash.isfile.return_value = True
    type(tar_info_slash).name = '/etc/hosts'

    # Next file contains rules!
    tar_info_rule = mock.create_autospec(tarfile.TarInfo)
    tar_info_rule.isfile.return_value = True
    type(tar_info_rule).name = 'I.contain.rules'

    mock_tar.getmembers.return_value = [
        tar_info_not_file,
        tar_info_dot_dot,
        tar_info_slash,
        tar_info_rule,
    ]

    # Simulate the tar member file that is going to be open.
    infile = mock.create_autospec(io.FileIO)
    infile.readlines.return_value = [
        b'# hey that\'s a nice file you have here\n',
        b'# alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:0;)',
        b'# drop udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:1;)',
        b'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:2;)',
        b'drop udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:3;)',
        b'\n',
        b'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:4;)',
        b'drop udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"ddos" sid:5;)',
    ]
    mock_tar.extractfile.return_value = infile

    # Simulate the output file that is going to be open.
    out = mock.create_autospec(io.FileIO)
    mock_open.return_value.__enter__.return_value = out
    return out, mock_tar

  @mock.patch.object(tarfile, 'open')
  @mock.patch.object(request, 'urlopen')
  @mock.patch.object(builtins, 'open')
  def test_whitelist(self, mock_open, mock_urlopen, mock_tar_open):
    out, mock_tar = self._prepare_mocks(mock_open, mock_urlopen, mock_tar_open)
    self._whitelist.append("sid:0")
    self._whitelist.append("msg:.*d?dos")
    buta = hikibuta.Hikibuta(
        self._url,
        self._outpath,
        self._whitelist,
        self._blacklist)
    buta.fetch_rules()

    # Test that we have what we expect in the output rules file.
    # First line is a comment, stays unchanged.
    self.assertTrue(
        mock.call(
            '# hey that\'s a nice file you have here\n'
        ) in out.write.call_args_list,
        out.write.call_args_list)
    # Second line was a commented rule but is whitelisted.
    self.assertTrue(
        mock.call(
            'alert udp $HOME_NET any -> $EXTERNAL_NET 53 '
            '(msg:"foobar" sid:0;)') in out.write.call_args_list,
        out.write.call_args_list)
    # The msg option matched, should be whitelisted.
    self.assertTrue(
        mock.call(
            'drop udp $HOME_NET any -> $EXTERNAL_NET 53 '
            '(msg:"ddos" sid:5;)') in out.write.call_args_list,
        out.write.call_args_list)
    # The rest should be commented out.
    self.assertTrue(
        mock.call(
            '#alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:2;)'
        ) in out.write.call_args_list,
        out.write.call_args_list)
    # We also keep the empty newlines as is.
    self.assertTrue(
        mock.call('\n') in out.write.call_args_list,
        out.write.call_args_list)

  @mock.patch.object(tarfile, 'open')
  @mock.patch.object(request, 'urlopen')
  @mock.patch.object(builtins, 'open')
  def test_blacklist(self, mock_open, mock_urlopen, mock_tar_open):
    out, mock_tar = self._prepare_mocks(mock_open, mock_urlopen, mock_tar_open)
    self._blacklist.append("sid:2")
    self._blacklist.append("msg:.*d?dos")
    buta = hikibuta.Hikibuta(
        self._url,
        self._outpath,
        self._whitelist,
        self._blacklist)
    buta.fetch_rules()

    # Test that we have what we expect in the output rules file.
    # First line is a comment, stays unchanged.
    self.assertTrue(
        mock.call(
            '# hey that\'s a nice file you have here\n'
        ) in out.write.call_args_list,
        out.write.call_args_list)
    # Second line was a commented rule but is not blacklisted,
    # it should now be uncommented.
    self.assertTrue(
        mock.call(
            'alert udp $HOME_NET any -> $EXTERNAL_NET 53 '
            '(msg:"foobar" sid:0;)') in out.write.call_args_list,
        out.write.call_args_list)
    # The msg option matched, should be blacklisted.
    self.assertTrue(
        mock.call(
            '#drop udp $HOME_NET any -> $EXTERNAL_NET 53 '
            '(msg:"ddos" sid:5;)') in out.write.call_args_list,
        out.write.call_args_list)
    # A non commented rule but blacklisted should now be commented.
    self.assertTrue(
        mock.call(
            '#alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"foobar" sid:2;)'
        ) in out.write.call_args_list,
        out.write.call_args_list)
    # We also keep the empty newlines as is.
    self.assertTrue(
        mock.call('\n') in out.write.call_args_list,
        out.write.call_args_list)


if __name__ == '__main__':
  unittest.main()

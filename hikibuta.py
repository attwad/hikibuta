import urllib
from urllib import request
import argparse
import configparser
import io
import logging
import os
import re
import sys
import tarfile
import time

import rule_parser

class Hikibuta(object):

  def __init__(self, archive_url, outpath, whitelist=None, blacklist=None):
    """Initialize the rules fetcher.

    Args:
      - archive_url: Where to download the rules from, reading this url should
        return an archive readable by the python tarfile module.
      - outpath: Directory where the files from the archive will be extracted to.
      - whitelist: List of key value pair strings separated by ":", the key is a
            message option and the value a python regexp that must match for the
            rule to be kept, all other rules will be commented out.
      - blacklist: List of key value pair strings separated by ":", the key is a
            message option and the value a python regexp that must not match for
            the rule to be kept, all other rules will be commented out.
            If a whitelist is present, the blacklist is ignored.
    """
    self._archive_url = archive_url
    self._outpath = outpath
    self._whitelist = []
    logging.info('whitelist: %s' % whitelist)
    self._whitelist.extend(self._get_match_patterns(whitelist))
    self._blacklist = []
    logging.info('blacklist: %s' % blacklist)
    if not self._whitelist:
      self._blacklist.extend(self._get_match_patterns(blacklist))

  @staticmethod
  def _get_match_patterns(rules):
    """Generates matching rules for filters in the config."""
    patterns = []
    for rule in rules:
      key, val = rule.split(':')
      patterns.append([key, re.compile(val)])
    return patterns

  def fetch_rules(self):
    logging.info("Fetching rules from '{}'".format(self._archive_url))
    resp = request.urlopen(self._archive_url)
    with io.BytesIO(resp.read()) as raw_archive:
      with tarfile.open(fileobj=raw_archive) as tar:
        logging.info('Downloaded archive containing files:')
        for member in tar.getmembers():
          if not member.isfile():
            logging.info(
                "tar member {} is not a file, passing...".format(member.name))
            continue
          if ".." in member.name:
            logging.error(
                "tar file member contained a possible malicious file (..): {}".format(
                    member.name))
            continue
          if member.name.startswith("/"):
            logging.error(
                "tar file member contained a possible malicious file (/): {}".format(
                    member.name))
            continue
          with open(os.path.join(self._outpath, member.name), "w") as f:
            for line in tar.extractfile(member).readlines():
              line = line.decode()
              if not rule_parser.Rule.is_rule_line(line):
                f.write(line)
                continue
              rule = rule_parser.Rule(line)
              if self._whitelist:
                for whitelist_key, whitelist_pattern in self._whitelist:
                  if (whitelist_key in rule._options and
                      whitelist_pattern.match(rule.options[whitelist_key])):
                    logging.debug('Whitelist rule {}:{} matched {}'.format(
                        whitelist_key, whitelist_pattern, line))
                    f.write(rule.as_uncommented)
                    break
                else:
                  logging.debug('No whitelist rule matched {}'.format(line))
                  f.write(rule.as_commented)
              elif self._blacklist:
                for blacklist_key, blacklist_pattern in self._blacklist:
                  if (blacklist_key in rule.options and
                      blacklist_pattern.match(rule.options[blacklist_key])):
                    logging.debug('Blacklist rule {}:{} matched {}'.format(
                        blacklist_key, blacklist_pattern, line))
                    f.write(rule.as_commented)
                    break
                else:
                  logging.debug('No blacklist rule matched {}'.format(line))
                  f.write(rule.as_uncommented)
              else:
                f.write(line)
      logging.info("Finished writing rules to {}".format(self._outpath))


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description=("Fetches and install suricata rules."))
  parser.add_argument('config', nargs='?', type=argparse.FileType('r'),
                      default='config.txt')
  parser.add_argument('-a', '--allow_non_https', default=False,
      help="Whether to allow downloading via non https:// links",
      action="store_true")
  parser.add_argument('-l', '--logfile', default='hikibuta', help=(
      'Verbose logfile name, override with empty for no log file.'
      'Run date will be appended to the file name.'))
  args = parser.parse_args()

  # Setup loggers first.
  if args.logfile:
    filename, ext = os.path.splitext(args.logfile)
    filename = filename + time.strftime("_%Y%m%d_%H%M%S", time.gmtime()) + ext
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
        datefmt='%m-%d %H:%M:%S',
        filename=filename,
        filemode='w')
    logging.info('Logging to file {}'.format(filename))
  console = logging.StreamHandler()
  console.setLevel(logging.INFO)
  logging.getLogger('').addHandler(console)

  # Parse the config
  config = configparser.ConfigParser()
  config.read_file(args.config)
  url = config['paths']['archive_url']
  logging.info('URL for download is {}'.format(url))
  if not args.allow_non_https and not url.startswith('https'):
    logging.error(
        'non https url downloads are not allowed, pass -a to the command-line '
        'if you are sure you want to do this.')
    sys.exit(1)

  # Finally start the fetch.
  bubu = Hikibuta(
      url,
      config['paths']['rules_dir'],
      [s for s in config['filters']['whitelist'].split(",") if s],
      [s for s in config['filters']['blacklist'].split(",") if s],
  )
  bubu.fetch_rules()

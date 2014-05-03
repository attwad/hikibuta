========
Hikibuta
========

Hikibuta will fetch and install Suricata rules following paths, urls and
filters given specified in a config file.
Ideal for cron jobs to keep your favourite IDS up to date.

.. code-block:: bash

  $ python hikibuta.py -h
    usage: hikibuta.py [-h] [-a] [-l LOGFILE] [config]

    Fetches and install suricata rules.

    positional arguments:
      config

    optional arguments:
      -h, --help            show this help message and exit
      -a, --allow_non_https
                            Whether to allow downloading via non https:// links
      -l LOGFILE, --logfile LOGFILE
                            Verbose logfile name, override with empty for no log
                            file.Run date will be appended to the file name.

Here is an sample config:

.. code-block::

  [paths]
  # Directory where the data from the rules archive will be extracted to.
  # Example:
  # rules_dir = /etc/suricata
  rules_dir = C:\Suricata

  # Where to fetch the rules from.
  archive_url = https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz

  # Each rule can be filtered by its options, filters consist of key value pairs
  # where the key is the option name and the value is a regexp that will be compiled
  # and matched against all rules that have this option.
  # Filters are ORed.
  # The blacklist is ignored if a whitelist is present.
  [filters]
  # Example:
  # blacklist = sid:2404012,msg:.*d?dos
  blacklist =
  whitelist =



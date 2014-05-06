import re

class Rule(object):
  """Represents a parsed rule."""

  IS_RULE_PATTERN = re.compile(r'^#*\s?(alert|reject|pass|drop)\s')

  def __init__(self, raw_line):
    self._raw = raw_line
    self._commented = False
    self._options = {}
    self._parse()

  @classmethod
  def is_rule_line(cls, line):
    return line and re.match(cls.IS_RULE_PATTERN, line)

  @property
  def as_uncommented(self):
    return re.sub(r'^#\s*', '', self._raw)

  @property
  def as_commented(self):
    return '#' + self.as_uncommented

  @property
  def commented(self):
    return self._commented

  @property
  def options(self):
    return self._options

  @property
  def action(self):
    return self._action

  @property
  def src_protocol(self):
    return self._src_protocol

  @property
  def src_net(self):
    return self._src_net

  @property
  def src_port(self):
    return self._src_port

  @property
  def direction(self):
    return self._dir

  @property
  def dst_net(self):
    return self._dst_net

  @property
  def dst_port(self):
    return self._dst_port

  @staticmethod
  def _get_within_spaces(s, start):
    end_index = start
    in_quotes = False
    while end_index < len(s) and (s[end_index] != ' ' or in_quotes):
      if s[end_index] == '"':
        in_quotes = not in_quotes
      end_index += 1
    return end_index

  def _parse(self):
    # String indexes.
    currenti = 0
    nexti = 0
    if self._raw.startswith("#"):
      self._commented = True
      while self._raw[currenti] == "#":
        currenti += 1
    else:
      self._commented = False
      currenti = 0
    # Action
    nexti = self._get_within_spaces(self._raw, currenti)
    self._action = self._raw[currenti:nexti]
    # src protocol
    currenti = nexti + 1
    nexti = self._get_within_spaces(self._raw, currenti)
    self._src_protocol = self._raw[currenti:nexti]
    # src net
    currenti = nexti + 1
    nexti = self._get_within_spaces(self._raw, currenti)
    self._src_net = self._raw[currenti:nexti]
    # src port
    currenti = nexti + 1
    nexti = self._get_within_spaces(self._raw, currenti)
    self._src_port = self._raw[currenti:nexti]
    # dir
    currenti = nexti + 1
    nexti = self._get_within_spaces(self._raw, currenti)
    self._dir = self._raw[currenti:nexti]
    # dest net
    currenti = nexti + 1
    nexti = self._get_within_spaces(self._raw, currenti)
    self._dst_net = self._raw[currenti:nexti]
    # dest port
    currenti = nexti + 1
    nexti = self._get_within_spaces(self._raw, currenti)
    self._dst_port = self._raw[currenti:nexti]
    # rule options
    while self._raw[nexti] == ' ' or self._raw[nexti] == '(':
      nexti+=1
    currenti = nexti
    while currenti < len(self._raw) - 1:
      nexti = self._get_within_spaces(self._raw, currenti)
      name, _, value = self._raw[currenti:nexti].partition(":")
      if value.endswith(")"):
        value = value[:-1]
      if value.endswith(";"):
        value = value[:-1]
      if name in self._options:
        self._options[name] += ('; ' + value)
      else:
        self._options[name] = value
      currenti = nexti + 1

  def __repr__(self):
    return (
        "Action       {}\n"
        "src protocol {}\n"
        "src net      {}\n"
        "src port     {}\n"
        "direction    {}\n"
        "dst net      {}\n"
        "dst port     {}\n"
        "options      {}\n"
        "".format(
            self._action,
            self._src_protocol,
            self._src_net,
            self._src_port,
            self._dir,
            self._dst_net,
            self._dst_port,
            self._options,
        ))

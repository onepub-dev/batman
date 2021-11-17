#! /usr/bin/env dcli

import 'package:dcli/dcli.dart' hide run;
import 'package:pci_file_monitor/src/entry_point.dart';

void main(List<String> arguments) {
  Settings().setVerbose(enabled: true);
  run(arguments);
}

#! /usr/bin/env dcli

import 'package:batman/src/entry_point.dart';
import 'package:batman/src/version/version.g.dart';

void main(List<String> arguments) {
  print('Batman $packageVersion');
  run(arguments);
}

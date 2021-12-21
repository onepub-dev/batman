import 'dart:io';

import 'package:dcli/dcli.dart';

import 'parsed_args.dart';

void run(List<String> args) {
  final ParsedArgs parsed;
  try {
    parsed = ParsedArgs.withArgs(args);
  } on ExitException catch (e) {
    exit(e.exitCode);
  }

  Shell.current.releasePrivileges();

  parsed.run();
}

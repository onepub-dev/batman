/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'dart:io';

import 'package:dcli/dcli.dart';

import 'parsed_args.dart';

Future<void> run(List<String> args) async {
  final ParsedArgs parsed;
  try {
    parsed = ParsedArgs.withArgs(args);
  } on ExitException catch (e) {
    exit(e.exitCode);
  }

  Shell.current.releasePrivileges();

  await parsed.run();
}

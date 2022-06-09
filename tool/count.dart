#! /usr/bin/env dcli

/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */



import 'dart:io';

// ignore: prefer_relative_imports
import 'package:dcli/dcli.dart';

/// Count the no. of files on the file system.
/// Must be run with sudo.

void main(List<String> args) {
  if (!Shell.current.isPrivilegedUser) {
    printerr(Shell.current.privilegesRequiredMessage('count'));
    exit(1);
  }

  var count = 0;
  find('*', includeHidden: true, workingDirectory: '/home')
      .forEach((file) => count++);

  print('Count: $count');
}

#! /usr/bin/env dcli

import 'dart:io';

import 'package:batman/src/version/version.g.dart';

// ignore: prefer_relative_imports
import 'package:dcli/dcli.dart';

/// Count the no. of files on the file system.
/// Must be run with sudo.

void main(List<String> args) {
  if (!Shell.current.isPrivilegedUser) {
    printerr(Shell.current.privilegesRequiredMessage('count'));
    exit(1);
  }

  int count = 0;
  find('*', includeHidden: true, workingDirectory: rootPath)
      .forEach((file) => count++);

  print('Count: $count');
}

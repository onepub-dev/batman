#! /usr/bin/env dcli

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

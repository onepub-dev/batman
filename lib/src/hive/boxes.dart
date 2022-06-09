/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */


import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:hive/hive.dart';

import 'model/file_checksum.dart';

class Boxes {
  factory Boxes() => _self;
  Boxes._internal();
  static late final Boxes _self = Boxes._internal();

  final fileChecksumKey = 'file_checksum';

  LazyBox<FileChecksum> get fileChecksumBox => _getChechsumBox();

  LazyBox<FileChecksum>? _fileChecksumBox;

  LazyBox<FileChecksum> _getChechsumBox() {
    _fileChecksumBox ??= _openChecksumBox();

    if (!_fileChecksumBox!.isOpen) {
      _fileChecksumBox = _openChecksumBox();
    }

    return _fileChecksumBox!;
  }

  LazyBox<FileChecksum> _openChecksumBox() {
    try {
      return waitForEx(Hive.openLazyBox<FileChecksum>(fileChecksumKey));
    } on FileSystemException catch (e) {
      if (e.osError != null && e.osError!.errorCode == 11) {
        printerr(red('The hive store is locked by another process'));
      }
      rethrow;
    }
  }
}

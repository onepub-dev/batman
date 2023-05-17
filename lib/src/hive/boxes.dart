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
  static final Boxes _self = Boxes._internal();

  final fileChecksumKey = 'file_checksum';

  Future<LazyBox<FileChecksum>> get fileChecksumBox async => _getChechsumBox();

  LazyBox<FileChecksum>? _fileChecksumBox;

  Future<LazyBox<FileChecksum>> _getChechsumBox() async {
    _fileChecksumBox ??= await _openChecksumBox();

    if (!_fileChecksumBox!.isOpen) {
      _fileChecksumBox = await _openChecksumBox();
    }

    return _fileChecksumBox!;
  }

  Future<LazyBox<FileChecksum>> _openChecksumBox() async {
    try {
      return await Hive.openLazyBox<FileChecksum>(fileChecksumKey);
    } on FileSystemException catch (e) {
      if (e.osError != null && e.osError!.errorCode == 11) {
        printerr(red('The hive store is locked by another process'));
      }
      rethrow;
    }
  }
}

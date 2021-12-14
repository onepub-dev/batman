import 'dart:io';

import 'package:dcli/dcli.dart';
import 'package:hive/hive.dart';

import 'model/file_checksum.dart';

class Boxes {
  factory Boxes() => _self;
  Boxes._internal();
  static late final Boxes _self = Boxes._internal();

  late LazyBox<FileChecksum> _checkSums = openChecksums();
  final fileChecksumKey = 'file_checksum';
  LazyBox<FileChecksum> get fileChecksums => _checkSums;

  LazyBox<FileChecksum> openChecksums() {
    try {
      return _checkSums =
          waitForEx(Hive.openLazyBox<FileChecksum>(fileChecksumKey));
    } on FileSystemException catch (e) {
      if (e.osError != null && e.osError!.errorCode == 11) {
        printerr(red('The hive store is locked by another processe'));
      }
      rethrow;
    }
  }
}

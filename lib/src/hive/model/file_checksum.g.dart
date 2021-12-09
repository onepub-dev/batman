// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'file_checksum.dart';

// **************************************************************************
// TypeAdapterGenerator
// **************************************************************************

class FileChecksumAdapter extends TypeAdapter<FileChecksum> {
  @override
  final int typeId = 1;

  @override
  FileChecksum read(BinaryReader reader) {
    final numOfFields = reader.readByte();
    final fields = <int, dynamic>{
      for (int i = 0; i < numOfFields; i++) reader.readByte(): reader.read(),
    };
    return FileChecksum(
      fields[1] as String,
      fields[2] as int,
    )
      ..pathHash = fields[0] as String
      ..marked = fields[3] as bool;
  }

  @override
  void write(BinaryWriter writer, FileChecksum obj) {
    writer
      ..writeByte(4)
      ..writeByte(0)
      ..write(obj.pathHash)
      ..writeByte(1)
      ..write(obj.pathTo)
      ..writeByte(2)
      ..write(obj.checksum)
      ..writeByte(3)
      ..write(obj.marked);
  }

  @override
  int get hashCode => typeId.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is FileChecksumAdapter &&
          runtimeType == other.runtimeType &&
          typeId == other.typeId;
}

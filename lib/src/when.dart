import 'package:intl/intl.dart';

String get when {
  final formatter = DateFormat('yyyy-MM-dd hh:mm');
  return formatter.format(DateTime.now());
}

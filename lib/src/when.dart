import 'package:intl/intl.dart';

String get when {
  final DateFormat formatter = DateFormat('yyyy-MM-dd hh:mm');
  return formatter.format(DateTime.now());
}

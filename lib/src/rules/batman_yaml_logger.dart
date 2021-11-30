import 'package:dcli/dcli.dart';

import '../log.dart';

/// Use the [BatmanYamlLogger] to log information about the log audit
/// settings as we load them.
/// This is used by the `batman rules` command to display
/// details about the audit rules as we load them.
class BatmanYamlLogger {
  static late final BatmanYamlLogger _self = BatmanYamlLogger._internal();

  factory BatmanYamlLogger() => _self;

  bool showWarnings = false;

  BatmanYamlLogger._internal();

  void warning(String Function() action) {
    if (showWarnings || Settings().isVerbose) {
      log('Warning: ${action()}');
    }
  }

  void info(String Function() action) {
    if (showWarnings || Settings().isVerbose) {
      log('Info: ${action()}');
    }
  }

  void load(String Function() action) {
    if (showWarnings || Settings().isVerbose) {
      log('Load: ${action()}');
    }
  }
}

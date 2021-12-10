import 'package:args/command_runner.dart';

import '../batman_settings.dart';
import '../hive/hive_store.dart';

///
class DoctorCommand extends Command<void> {
  ///
  DoctorCommand();

  @override
  String get description => 'Displays the Batman settings';

  @override
  String get name => 'doctor';

  @override
  void run() {
    BatmanSettings.load();
    print('Hive path: ${BatmanSettings().pathToDb}');

    print('Baseline Files: ${HiveStore().checksumCount()}');

    print('Rules path: ${BatmanSettings.pathToRules}');
  }
}

import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../dcli/resources/generated/resource_registry.g.dart';

import '../log.dart';
import '../batman_settings.dart';

class InstallCommand extends Command<void> {
  @override
  String get description => 'Configures batman.';

  @override
  String get name => 'install';

  @override
  void run() {
    Settings().setVerbose(enabled: globalResults!['verbose'] as bool);
    final pathToBatman = dirname(BatmanSettings.pathToRules);
    if (!exists(pathToBatman)) {
      createDir(pathToBatman, recursive: true);
    }

    ResourceRegistry.resources[basename(BatmanSettings.pathToRules)]!
        .unpack(BatmanSettings.pathToRules);

    log("Run 'batman baseline' to set an initial baseline");
    log("Schedule 'batman scan' to run at least weekly.");
    log(green('Installation complete.'));
  }
}

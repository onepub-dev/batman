import 'package:args/command_runner.dart';
import 'package:dcli/dcli.dart';
import '../dcli/resources/generated/resource_registry.g.dart';

import '../rules.dart';

class InstallCommand extends Command<void> {
  @override
  String get description => 'Configures pcifim.';

  @override
  String get name => 'install';

  @override
  void run() {
    final pathToPciFim = dirname(Rules.pathToRules);
    if (!exists(pathToPciFim)) {
      createDir(pathToPciFim, recursive: true);
    }

    ResourceRegistry.resources[basename(Rules.pathToRules)]!
        .unpack(Rules.pathToRules);

    print(green('installation complete'));
    print("run 'pcifim baseline' to set an initial baseline");
  }
}

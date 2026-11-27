File `*.txt` qui vengono copiati in `/etc/waf/lists/` a ogni reload.

`custom-reputation.txt` (un IP/CIDR per riga) è trattato come la `AWSManagedIPReputationList`:
gli IP elencati sono bloccati dalla regola di reputazione.

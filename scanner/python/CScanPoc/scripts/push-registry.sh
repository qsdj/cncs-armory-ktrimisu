 #!/bin/bash
for i in $( docker images ); do
    echo item: $i
done
        
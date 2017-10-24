# cscnetwork

### Pull from Github to update the code on VM
Remove the original project folder on VM and pull the latest version from Github.

```cd ~ && sudo rm -rf cs144_lab3/```


```git clone https://github.com/luzehua/cscnetwork.git cs144_lab3/ && 
cd cs144_lab3/ && git checkout --track remotes/origin/standalone && 
./config.sh && ln -s ../pox && cd router/ && make && ./sr```


# sneakynet


## Set up

```sh
git clone https://github.com/DecentLabs/sneakynet
pip install -r requirements.txt
npm install
python main.py
```

## Initializing the database before first run

```sh
npm run db:init
```
## Required improvements

- Omni-directional sync
- Known nodes directory
- ~~User/Message/thread hashes as IDs~~
- Synchronization chain
- Sync data should be encrypted
- Optimized sync/serialization format
- Database queries are extremely inefficient
- Thread titles should be UTF8
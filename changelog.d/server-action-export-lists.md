section: Fixed
docs: none, no change to what the Server Action check reports; it reads export lists in bounded time

- **Crafted export lists can't slow the Server Action check down.** A file full
  of unclosed `export {` lists made the check reread the rest of the file each
  time. Lists are now read once; an export list that never closes marks the file
  as not fully checked (exit 2) instead of dropping its actions.

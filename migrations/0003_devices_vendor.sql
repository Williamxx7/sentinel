-- Optional vendor (MAC OUI) reported by nmap, e.g. "Apple, Inc.".
ALTER TABLE devices ADD COLUMN vendor TEXT;

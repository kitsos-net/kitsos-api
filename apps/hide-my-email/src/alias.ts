const NOUNS = [
  "house", "river", "cloud", "forest", "meadow", "harbor", "canyon", "summit",
  "island", "valley", "garden", "bridge", "tower", "orchard", "lagoon", "prairie",
  "glacier", "coral", "willow", "cedar", "falcon", "otter", "heron", "lynx",
];

const ADJECTIVES = [
  "exclusive", "quiet", "amber", "silver", "gentle", "hidden", "bright", "steady",
  "distant", "coastal", "golden", "crisp", "mellow", "swift", "calm", "wild",
  "cobalt", "dusky", "vivid", "quaint", "rustic", "brisk", "misty", "sunny",
];

/** Generates a memorable-ish local part like "house.exclusive.15". */
export function generateAlias(): string {
  const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
  const adjective = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
  const number = Math.floor(Math.random() * 100);
  return `${noun}.${adjective}.${number}`;
}

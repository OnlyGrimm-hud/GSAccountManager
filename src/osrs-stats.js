const HISCORE_ENDPOINT = 'https://secure.runescape.com/m=hiscore_oldschool/index_lite.ws';

const SKILL_ORDER = [
  'overall',
  'attack',
  'defence',
  'strength',
  'hitpoints',
  'ranged',
  'prayer',
  'magic',
  'cooking',
  'woodcutting',
  'fletching',
  'fishing',
  'firemaking',
  'crafting',
  'smithing',
  'mining',
  'herblore',
  'agility',
  'thieving',
  'slayer',
  'farming',
  'runecraft',
  'hunter',
  'construction'
];

function parseHiscoreLite(body) {
  const lines = String(body || '').trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < SKILL_ORDER.length) throw new Error('Hiscore response did not include the expected skill rows.');

  const skills = {};
  SKILL_ORDER.forEach((skill, index) => {
    const [rankRaw, levelRaw, xpRaw] = lines[index].split(',');
    skills[skill] = {
      rank: numberOrNull(rankRaw),
      level: numberOrNull(levelRaw),
      xp: numberOrNull(xpRaw)
    };
  });

  const core = {
    attack: safeLevel(skills.attack),
    strength: safeLevel(skills.strength),
    defence: safeLevel(skills.defence),
    ranged: safeLevel(skills.ranged),
    prayer: safeLevel(skills.prayer),
    magic: safeLevel(skills.magic),
    hitpoints: safeLevel(skills.hitpoints)
  };

  return {
    total_level: safeLevel(skills.overall),
    total_xp: Math.max(0, skills.overall.xp || 0),
    combat_level: estimateCombatLevel(core),
    ...core,
    skills
  };
}

async function fetchPublicStats(displayName, fetchImpl = global.fetch) {
  const name = String(displayName || '').trim().replace(/\s+/g, ' ');
  if (!name) {
    return failedStats('failed', 'Display name is required for OSRS stats lookup.');
  }
  if (typeof fetchImpl !== 'function') {
    return failedStats('failed', 'Stats lookup is unavailable in this Node runtime.');
  }

  const url = `${HISCORE_ENDPOINT}?player=${encodeURIComponent(name)}`;
  try {
    const response = await fetchImpl(url, {
      headers: {
        'User-Agent': 'GSAccountManager/0.1.0 (+https://gsaccountmanager.com)'
      }
    });
    if (response.status === 404) return failedStats('not_found', 'Display name was not found on public OSRS hiscores.');
    if (!response.ok) return failedStats('failed', `Public OSRS hiscores returned HTTP ${response.status}.`);
    const parsed = parseHiscoreLite(await response.text());
    return {
      display_name: name,
      source: 'osrs_hiscores',
      status: 'ok',
      error_message: null,
      ...parsed
    };
  } catch (error) {
    return failedStats('failed', 'Public OSRS stats lookup failed.');
  }
}

function estimateCombatLevel(stats) {
  const attack = Number(stats.attack || 1);
  const strength = Number(stats.strength || 1);
  const defence = Number(stats.defence || 1);
  const ranged = Number(stats.ranged || 1);
  const prayer = Number(stats.prayer || 1);
  const magic = Number(stats.magic || 1);
  const hitpoints = Number(stats.hitpoints || 10);
  const base = 0.25 * (defence + hitpoints + Math.floor(prayer / 2));
  const melee = 0.325 * (attack + strength);
  const range = 0.325 * Math.floor(ranged * 1.5);
  const mage = 0.325 * Math.floor(magic * 1.5);
  return Math.max(3, Math.floor(base + Math.max(melee, range, mage)));
}

function failedStats(status, message) {
  return {
    display_name: null,
    total_level: null,
    total_xp: null,
    combat_level: null,
    attack: null,
    strength: null,
    defence: null,
    ranged: null,
    prayer: null,
    magic: null,
    hitpoints: null,
    skills: {},
    source: 'osrs_hiscores',
    status,
    error_message: message
  };
}

function safeLevel(skill) {
  return Math.max(0, Number(skill && skill.level > 0 ? skill.level : 0));
}

function numberOrNull(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

module.exports = {
  HISCORE_ENDPOINT,
  SKILL_ORDER,
  estimateCombatLevel,
  fetchPublicStats,
  parseHiscoreLite
};

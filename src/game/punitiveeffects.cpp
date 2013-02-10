#include "punitiveeffects.h"

namespace punitiveeffects
{
	vector<punitiveeffect *> effects;

	punitiveeffect* search(uint ip, int typemask)
	{
		loopv(effects) {
			if(((effects[i]->ip & effects[i]->mask) == (ip & effects[i]->mask)) && (typemask & effects[i]->type))
			{
				return effects[i];
			}
		}
		return NULL;
	}

	punitiveeffect* update(uint id, uint ip, uint mask, int type, const char* reason)
	{
		punitiveeffect* effect = NULL;

		loopv(effects) if(effects[i]->id == id)
		{
			effect = effects[i];
			break;
		}

		if(!effect)
		{
			effect = new punitiveeffect;
			effects.add(effect);
		}

		effect->id = id;
		effect->ip = ip;
		effect->mask = mask;
		effect->type = type;

		int len = strlen(reason);
		effect->reason = (char*)malloc((len+1)*sizeof(char));
		strncpy(effect->reason, reason, len+1);

		return effect;
	}

	punitiveeffect* remove(uint id)
	{
		loopv(effects) if(effects[i]->id == id)
		{
			punitiveeffect* effect = effects[i];
			effects.remove(i);
			return effect;
		}
		return NULL;
	}

	int type_id(const char* type_name)
	{
		int len = strlen(type_name);
		if(!strncmp(type_name, "ban", len)) return BAN;
		if(!strncmp(type_name, "mute", len)) return MUTE;
		if(!strncmp(type_name, "spectate", len)) return SPECTATE;
		if(!strncmp(type_name, "limit", len)) return LIMIT;
		else return LIMIT;
	}

	const char* type_name(int type_id, bool past_tense)
	{
		switch(type_id) {
		case BAN:
			return past_tense ? "banned" : "ban";
		case MUTE:
			return past_tense ? "muted" : "mute";
		case SPECTATE:
			return past_tense ? "spectated" : "spectate";
		case LIMIT:
		default:
			return past_tense ? "limited" : "limit";
		}
	}
}

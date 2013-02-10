namespace punitiveeffects
{
	enum { BAN = 1, MUTE = 2, SPECTATE = 4, LIMIT = 8};

	struct punitiveeffect
	{
		uint id;
		uint ip;
		uint mask;
		int type;
		char* reason;
	};

	extern vector<punitiveeffect *> effects;

	punitiveeffect* search(uint ip, int typemask);

	punitiveeffect* update(uint id, uint ip, uint mask, int type, const char* reason);
	punitiveeffect* remove(uint id);

	int type_id(const char* type_name);
	const char* type_name(int type_id, bool past_tense=false);
}

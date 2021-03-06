APPNAME=redeclipse
APPCLIENT=reclient
APPSERVER=reserver

#CXXFLAGS= -ggdb3
CXXFLAGS= -O3 -fomit-frame-pointer
override CXXFLAGS+= -Wall -fsigned-char -fno-exceptions -fno-rtti

PLATFORM= $(shell uname -s)
PLATFORM_SUFFIX=_native

INCLUDES= -Ishared -Iengine -Igame -Ienet/include

STRIP=
ifeq (,$(findstring -g,$(CXXFLAGS)))
ifeq (,$(findstring -pg,$(CXXFLAGS)))
	STRIP=strip
endif
endif

MV=mv

ifneq (,$(findstring MINGW,$(PLATFORM)))
WINDRES= windres
ifneq (,$(findstring 64,$(PLATFORM)))
WINLIB=lib64
WINBIN=../bin64
override CXX+= -m64
override WINDRES+= -F pe-x86-64
else
WINLIB=lib
WINBIN=../bin
override CXX+= -m32
override WINDRES+= -F pe-i386
endif
ifneq (,$(findstring TDM,$(PLATFORM)))
STD_LIBS=
else
STD_LIBS= -static-libgcc -static-libstdc++
endif
CLIENT_INCLUDES= $(INCLUDES) -Iinclude
CLIENT_LIBS= -mwindows $(STD_LIBS) -L$(WINBIN) -L$(WINLIB) -lSDL -lSDL_image -lSDL_mixer -lzlib1 -lopengl32 -lenet -lws2_32 -lwinmm
else
CLIENT_INCLUDES= $(INCLUDES) -I/usr/X11R6/include `sdl-config --cflags`
CLIENT_LIBS= -Lenet/.libs -lenet -L/usr/X11R6/lib -lX11 `sdl-config --libs` -lSDL_image -lSDL_mixer -lz -lGL
endif
ifeq ($(PLATFORM),Linux)
CLIENT_LIBS+= -lrt
endif
CLIENT_OBJS= \
	shared/crypto.o \
	shared/geom.o \
	shared/stream.o \
	shared/tools.o \
	shared/zip.o \
	engine/bih.o \
	engine/blend.o \
	engine/blob.o \
	engine/client.o \
	engine/command.o \
	engine/console.o \
	engine/decal.o \
	engine/dynlight.o \
	engine/glare.o \
	engine/grass.o \
	engine/irc.o	\
	engine/lightmap.o \
	engine/main.o \
	engine/material.o \
	engine/menus.o \
	engine/movie.o \
	engine/normal.o \
	engine/octa.o \
	engine/octaedit.o \
	engine/octarender.o \
	engine/physics.o \
	engine/pvs.o \
	engine/rendergl.o \
	engine/rendermodel.o \
	engine/renderparticles.o \
	engine/rendersky.o \
	engine/rendertext.o \
	engine/renderva.o \
	engine/server.o \
	engine/serverbrowser.o \
	engine/shader.o \
	engine/shadowmap.o \
	engine/sound.o \
	engine/texture.o \
	engine/ui.o \
	engine/water.o \
	engine/world.o \
	engine/worldio.o \
	game/ai.o \
	game/client.o \
	game/capture.o \
	game/defend.o \
	game/bomber.o \
	game/entities.o \
	game/game.o \
	game/hud.o \
	game/physics.o \
	game/projs.o \
	game/scoreboard.o \
	game/server.o \
	game/waypoint.o \
	game/weapons.o

CLIENT_PCH= shared/cube.h.gch engine/engine.h.gch

ifneq (,$(findstring MINGW,$(PLATFORM)))
SERVER_INCLUDES= -DSTANDALONE $(INCLUDES) -Iinclude
SERVER_LIBS= -mwindows $(STD_LIBS) -L$(WINBIN) -L$(WINLIB) -lzlib1 -lenet -lws2_32 -lwinmm
else
SERVER_INCLUDES= -DSTANDALONE $(INCLUDES)
SERVER_LIBS= -Lenet/.libs -lenet -lz
endif
SERVER_OBJS= \
	shared/crypto-standalone.o \
	shared/geom-standalone.o \
	shared/stream-standalone.o \
	shared/tools-standalone.o \
	engine/command-standalone.o \
	engine/irc-standalone.o \
	engine/master-standalone.o \
	engine/server-standalone.o \
	game/server-standalone.o

default: all

enet/Makefile:
	cd enet; ./configure --enable-shared=no --enable-static=yes

libenet: enet/Makefile
	$(MAKE) -C enet/ all

clean-enet: enet/Makefile
	$(MAKE) -C enet/ clean

clean: clean-client clean-server

clean-client:
	@rm -fv $(CLIENT_PCH) $(CLIENT_OBJS) $(APPCLIENT)

clean-server:
	@rm -fv $(SERVER_OBJS) $(APPSERVER)

%.h.gch: %.h
	$(CXX) $(CXXFLAGS) -o $(subst .h.gch,.tmp.h.gch,$@) $(subst .h.gch,.h,$@)
	$(MV) $(subst .h.gch,.tmp.h.gch,$@) $@

%-standalone.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $(subst -standalone.o,.cpp,$@)

$(CLIENT_OBJS): CXXFLAGS += $(CLIENT_INCLUDES)
$(filter shared/%,$(CLIENT_OBJS)): $(filter shared/%,$(CLIENT_PCH))
$(filter engine/%,$(CLIENT_OBJS)): $(filter engine/%,$(CLIENT_PCH))
$(filter game/%,$(CLIENT_OBJS)): $(filter game/%,$(CLIENT_PCH))

$(SERVER_OBJS): CXXFLAGS += $(SERVER_INCLUDES)

ifneq (,$(findstring MINGW,$(PLATFORM)))
client: $(CLIENT_OBJS)
	$(WINDRES) -i $(APPNAME).rc -J rc -o $(APPNAME).res -O coff 
	$(CXX) $(CXXFLAGS) -o $(WINBIN)/$(APPCLIENT).exe $(APPNAME).res $(CLIENT_OBJS) $(CLIENT_LIBS)

server: $(SERVER_OBJS)
	$(WINDRES) -i $(APPNAME).rc -J rc -o $(APPNAME).res -O coff 
	$(CXX) $(CXXFLAGS) -o $(WINBIN)/$(APPSERVER).exe $(APPNAME).res $(SERVER_OBJS) $(SERVER_LIBS)

install-client: client
ifneq (,$(STRIP))
	$(STRIP) $(WINBIN)/$(APPCLIENT).exe
endif

install-server: server
ifneq (,$(STRIP))
	$(STRIP) $(WINBIN)/$(APPSERVER).exe
endif
else
client: libenet $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(APPCLIENT) $(CLIENT_OBJS) $(CLIENT_LIBS)
ifneq (,$(STRIP))
	$(STRIP) $(APPCLIENT)
endif

server: libenet $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(APPSERVER) $(SERVER_OBJS) $(SERVER_LIBS)
ifneq (,$(STRIP))
	$(STRIP) $(APPSERVER)
endif

install-client: client
	install -d ../bin
	install -m 755 $(APPCLIENT) ../bin/$(APPCLIENT)$(PLATFORM_SUFFIX)

install-server: server
	install -d ../bin
	install -m 755 $(APPSERVER) ../bin/$(APPSERVER)$(PLATFORM_SUFFIX)

shared/cube2font.o: shared/cube2font.c
	$(CXX) $(CXXFLAGS) -c -o $@ $< `freetype-config --cflags`

cube2font: shared/cube2font.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o cube2font shared/cube2font.o `freetype-config --libs` -lz

install-cube2font: cube2font
	install -d ../bin
	install -m 755 cube2font ../bin/cube2font
endif

install: install-client install-server

depend:
	makedepend -Y -Ishared -Iengine -Igame $(subst .o,.cpp,$(CLIENT_OBJS))
	makedepend -a -o-standalone.o -Y -Ishared -Iengine -Igame -DSTANDALONE $(subst -standalone.o,.cpp,$(SERVER_OBJS))
	makedepend -a -o.h.gch -Y -Ishared -Iengine -Igame $(subst .h.gch,.h,$(CLIENT_PCH))

all: server

include system-install.mk
include dist.mk

engine/engine.h.gch: shared/cube.h.gch

# DO NOT DELETE

shared/crypto.o: shared/cube.h shared/tools.h shared/command.h shared/geom.h
shared/crypto.o: shared/ents.h shared/iengine.h shared/igame.h
shared/geom.o: shared/cube.h shared/tools.h shared/command.h shared/geom.h
shared/geom.o: shared/ents.h shared/iengine.h shared/igame.h
shared/stream.o: shared/cube.h shared/tools.h shared/command.h shared/geom.h
shared/stream.o: shared/ents.h shared/iengine.h shared/igame.h
shared/tools.o: shared/cube.h shared/tools.h shared/command.h shared/geom.h
shared/tools.o: shared/ents.h shared/iengine.h shared/igame.h
shared/zip.o: shared/cube.h shared/tools.h shared/command.h shared/geom.h
shared/zip.o: shared/ents.h shared/iengine.h shared/igame.h
engine/bih.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/bih.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/bih.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/bih.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/bih.o: engine/varray.h
engine/blend.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/blend.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/blend.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/blend.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/blend.o: engine/model.h engine/varray.h
engine/blob.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/blob.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/blob.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/blob.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/blob.o: engine/varray.h
engine/client.o: engine/engine.h shared/cube.h shared/tools.h
engine/client.o: shared/command.h shared/geom.h shared/ents.h
engine/client.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/client.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/client.o: engine/texture.h engine/model.h engine/varray.h
engine/command.o: engine/engine.h shared/cube.h shared/tools.h
engine/command.o: shared/command.h shared/geom.h shared/ents.h
engine/command.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/command.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/command.o: engine/texture.h engine/model.h engine/varray.h
engine/console.o: engine/engine.h shared/cube.h shared/tools.h
engine/console.o: shared/command.h shared/geom.h shared/ents.h
engine/console.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/console.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/console.o: engine/texture.h engine/model.h engine/varray.h
engine/decal.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/decal.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/decal.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/decal.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/decal.o: engine/model.h engine/varray.h
engine/dynlight.o: engine/engine.h shared/cube.h shared/tools.h
engine/dynlight.o: shared/command.h shared/geom.h shared/ents.h
engine/dynlight.o: shared/iengine.h shared/igame.h engine/irc.h
engine/dynlight.o: engine/sound.h engine/world.h engine/octa.h
engine/dynlight.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/dynlight.o: engine/model.h engine/varray.h
engine/glare.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/glare.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/glare.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/glare.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/glare.o: engine/model.h engine/varray.h engine/rendertarget.h
engine/grass.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/grass.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/grass.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/grass.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/grass.o: engine/model.h engine/varray.h
engine/irc.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/irc.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/irc.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/irc.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/irc.o: engine/varray.h
engine/lightmap.o: engine/engine.h shared/cube.h shared/tools.h
engine/lightmap.o: shared/command.h shared/geom.h shared/ents.h
engine/lightmap.o: shared/iengine.h shared/igame.h engine/irc.h
engine/lightmap.o: engine/sound.h engine/world.h engine/octa.h
engine/lightmap.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/lightmap.o: engine/model.h engine/varray.h
engine/main.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/main.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/main.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/main.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/main.o: engine/varray.h
engine/material.o: engine/engine.h shared/cube.h shared/tools.h
engine/material.o: shared/command.h shared/geom.h shared/ents.h
engine/material.o: shared/iengine.h shared/igame.h engine/irc.h
engine/material.o: engine/sound.h engine/world.h engine/octa.h
engine/material.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/material.o: engine/model.h engine/varray.h
engine/menus.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/menus.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/menus.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/menus.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/menus.o: engine/model.h engine/varray.h
engine/movie.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/movie.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/movie.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/movie.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/movie.o: engine/model.h engine/varray.h
engine/normal.o: engine/engine.h shared/cube.h shared/tools.h
engine/normal.o: shared/command.h shared/geom.h shared/ents.h
engine/normal.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/normal.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/normal.o: engine/texture.h engine/model.h engine/varray.h
engine/octa.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/octa.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/octa.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/octa.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/octa.o: engine/varray.h
engine/octaedit.o: engine/engine.h shared/cube.h shared/tools.h
engine/octaedit.o: shared/command.h shared/geom.h shared/ents.h
engine/octaedit.o: shared/iengine.h shared/igame.h engine/irc.h
engine/octaedit.o: engine/sound.h engine/world.h engine/octa.h
engine/octaedit.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/octaedit.o: engine/model.h engine/varray.h
engine/octarender.o: engine/engine.h shared/cube.h shared/tools.h
engine/octarender.o: shared/command.h shared/geom.h shared/ents.h
engine/octarender.o: shared/iengine.h shared/igame.h engine/irc.h
engine/octarender.o: engine/sound.h engine/world.h engine/octa.h
engine/octarender.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/octarender.o: engine/model.h engine/varray.h
engine/physics.o: engine/engine.h shared/cube.h shared/tools.h
engine/physics.o: shared/command.h shared/geom.h shared/ents.h
engine/physics.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/physics.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/physics.o: engine/texture.h engine/model.h engine/varray.h
engine/physics.o: engine/mpr.h
engine/pvs.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/pvs.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/pvs.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/pvs.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/pvs.o: engine/varray.h
engine/rendergl.o: engine/engine.h shared/cube.h shared/tools.h
engine/rendergl.o: shared/command.h shared/geom.h shared/ents.h
engine/rendergl.o: shared/iengine.h shared/igame.h engine/irc.h
engine/rendergl.o: engine/sound.h engine/world.h engine/octa.h
engine/rendergl.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/rendergl.o: engine/model.h engine/varray.h
engine/rendermodel.o: engine/engine.h shared/cube.h shared/tools.h
engine/rendermodel.o: shared/command.h shared/geom.h shared/ents.h
engine/rendermodel.o: shared/iengine.h shared/igame.h engine/irc.h
engine/rendermodel.o: engine/sound.h engine/world.h engine/octa.h
engine/rendermodel.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/rendermodel.o: engine/model.h engine/varray.h engine/ragdoll.h
engine/rendermodel.o: engine/animmodel.h engine/vertmodel.h
engine/rendermodel.o: engine/skelmodel.h engine/md2.h engine/md3.h
engine/rendermodel.o: engine/md5.h engine/obj.h engine/smd.h engine/iqm.h
engine/renderparticles.o: engine/engine.h shared/cube.h shared/tools.h
engine/renderparticles.o: shared/command.h shared/geom.h shared/ents.h
engine/renderparticles.o: shared/iengine.h shared/igame.h engine/irc.h
engine/renderparticles.o: engine/sound.h engine/world.h engine/octa.h
engine/renderparticles.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/renderparticles.o: engine/model.h engine/varray.h
engine/renderparticles.o: engine/rendertarget.h engine/depthfx.h
engine/renderparticles.o: engine/lensflare.h engine/explosion.h
engine/renderparticles.o: engine/lightning.h
engine/rendersky.o: engine/engine.h shared/cube.h shared/tools.h
engine/rendersky.o: shared/command.h shared/geom.h shared/ents.h
engine/rendersky.o: shared/iengine.h shared/igame.h engine/irc.h
engine/rendersky.o: engine/sound.h engine/world.h engine/octa.h
engine/rendersky.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/rendersky.o: engine/model.h engine/varray.h
engine/rendertext.o: engine/engine.h shared/cube.h shared/tools.h
engine/rendertext.o: shared/command.h shared/geom.h shared/ents.h
engine/rendertext.o: shared/iengine.h shared/igame.h engine/irc.h
engine/rendertext.o: engine/sound.h engine/world.h engine/octa.h
engine/rendertext.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/rendertext.o: engine/model.h engine/varray.h
engine/renderva.o: engine/engine.h shared/cube.h shared/tools.h
engine/renderva.o: shared/command.h shared/geom.h shared/ents.h
engine/renderva.o: shared/iengine.h shared/igame.h engine/irc.h
engine/renderva.o: engine/sound.h engine/world.h engine/octa.h
engine/renderva.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/renderva.o: engine/model.h engine/varray.h
engine/server.o: engine/engine.h shared/cube.h shared/tools.h
engine/server.o: shared/command.h shared/geom.h shared/ents.h
engine/server.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/server.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/server.o: engine/texture.h engine/model.h engine/varray.h
engine/serverbrowser.o: engine/engine.h shared/cube.h shared/tools.h
engine/serverbrowser.o: shared/command.h shared/geom.h shared/ents.h
engine/serverbrowser.o: shared/iengine.h shared/igame.h engine/irc.h
engine/serverbrowser.o: engine/sound.h engine/world.h engine/octa.h
engine/serverbrowser.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/serverbrowser.o: engine/model.h engine/varray.h
engine/shader.o: engine/engine.h shared/cube.h shared/tools.h
engine/shader.o: shared/command.h shared/geom.h shared/ents.h
engine/shader.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/shader.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/shader.o: engine/texture.h engine/model.h engine/varray.h
engine/shadowmap.o: engine/engine.h shared/cube.h shared/tools.h
engine/shadowmap.o: shared/command.h shared/geom.h shared/ents.h
engine/shadowmap.o: shared/iengine.h shared/igame.h engine/irc.h
engine/shadowmap.o: engine/sound.h engine/world.h engine/octa.h
engine/shadowmap.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/shadowmap.o: engine/model.h engine/varray.h engine/rendertarget.h
engine/sound.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/sound.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/sound.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/sound.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/sound.o: engine/model.h engine/varray.h
engine/texture.o: engine/engine.h shared/cube.h shared/tools.h
engine/texture.o: shared/command.h shared/geom.h shared/ents.h
engine/texture.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/texture.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/texture.o: engine/texture.h engine/model.h engine/varray.h
engine/texture.o: engine/scale.h
engine/ui.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/ui.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/ui.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/ui.o: engine/lightmap.h engine/bih.h engine/texture.h engine/model.h
engine/ui.o: engine/varray.h engine/textedit.h
engine/water.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/water.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/water.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/water.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/water.o: engine/model.h engine/varray.h
engine/world.o: engine/engine.h shared/cube.h shared/tools.h shared/command.h
engine/world.o: shared/geom.h shared/ents.h shared/iengine.h shared/igame.h
engine/world.o: engine/irc.h engine/sound.h engine/world.h engine/octa.h
engine/world.o: engine/lightmap.h engine/bih.h engine/texture.h
engine/world.o: engine/model.h engine/varray.h
engine/worldio.o: engine/engine.h shared/cube.h shared/tools.h
engine/worldio.o: shared/command.h shared/geom.h shared/ents.h
engine/worldio.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
engine/worldio.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
engine/worldio.o: engine/texture.h engine/model.h engine/varray.h
game/ai.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/ai.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/ai.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/ai.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/ai.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/ai.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/ai.o: game/bomber.h
game/client.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/client.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/client.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/client.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/client.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/client.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/client.o: game/bomber.h
game/capture.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/capture.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/capture.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/capture.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/capture.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/capture.o: game/team.h game/ai.h game/vars.h game/capture.h
game/capture.o: game/defend.h game/bomber.h
game/defend.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/defend.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/defend.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/defend.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/defend.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/defend.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/defend.o: game/bomber.h
game/bomber.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/bomber.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/bomber.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/bomber.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/bomber.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/bomber.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/bomber.o: game/bomber.h
game/entities.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/entities.o: shared/command.h shared/geom.h shared/ents.h
game/entities.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
game/entities.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
game/entities.o: engine/texture.h engine/model.h engine/varray.h
game/entities.o: game/weapons.h game/gamemode.h game/team.h game/ai.h
game/entities.o: game/vars.h game/capture.h game/defend.h game/bomber.h
game/game.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/game.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/game.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/game.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/game.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/game.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/game.o: game/bomber.h
game/hud.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/hud.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/hud.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/hud.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/hud.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/hud.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/hud.o: game/bomber.h game/compass.h
game/physics.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/physics.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/physics.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/physics.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/physics.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/physics.o: game/team.h game/ai.h game/vars.h game/capture.h
game/physics.o: game/defend.h game/bomber.h
game/projs.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/projs.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/projs.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/projs.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/projs.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/projs.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/projs.o: game/bomber.h
game/scoreboard.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/scoreboard.o: shared/command.h shared/geom.h shared/ents.h
game/scoreboard.o: shared/iengine.h shared/igame.h engine/irc.h
game/scoreboard.o: engine/sound.h engine/world.h engine/octa.h
game/scoreboard.o: engine/lightmap.h engine/bih.h engine/texture.h
game/scoreboard.o: engine/model.h engine/varray.h game/weapons.h
game/scoreboard.o: game/gamemode.h game/team.h game/ai.h game/vars.h
game/scoreboard.o: game/capture.h game/defend.h game/bomber.h
game/server.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/server.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/server.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/server.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/server.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/server.o: game/team.h game/ai.h game/vars.h game/capture.h game/defend.h
game/server.o: game/bomber.h game/auth.h game/capturemode.h game/defendmode.h
game/server.o: game/bombermode.h game/duelmut.h game/aiman.h game/extinfo.h
game/waypoint.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/waypoint.o: shared/command.h shared/geom.h shared/ents.h
game/waypoint.o: shared/iengine.h shared/igame.h engine/irc.h engine/sound.h
game/waypoint.o: engine/world.h engine/octa.h engine/lightmap.h engine/bih.h
game/waypoint.o: engine/texture.h engine/model.h engine/varray.h
game/waypoint.o: game/weapons.h game/gamemode.h game/team.h game/ai.h
game/waypoint.o: game/vars.h game/capture.h game/defend.h game/bomber.h
game/weapons.o: game/game.h engine/engine.h shared/cube.h shared/tools.h
game/weapons.o: shared/command.h shared/geom.h shared/ents.h shared/iengine.h
game/weapons.o: shared/igame.h engine/irc.h engine/sound.h engine/world.h
game/weapons.o: engine/octa.h engine/lightmap.h engine/bih.h engine/texture.h
game/weapons.o: engine/model.h engine/varray.h game/weapons.h game/gamemode.h
game/weapons.o: game/team.h game/ai.h game/vars.h game/capture.h
game/weapons.o: game/defend.h game/bomber.h

shared/crypto-standalone.o: shared/cube.h shared/tools.h shared/command.h
shared/crypto-standalone.o: shared/geom.h shared/ents.h shared/iengine.h
shared/crypto-standalone.o: shared/igame.h
shared/geom-standalone.o: shared/cube.h shared/tools.h shared/command.h
shared/geom-standalone.o: shared/geom.h shared/ents.h shared/iengine.h
shared/geom-standalone.o: shared/igame.h
shared/stream-standalone.o: shared/cube.h shared/tools.h shared/command.h
shared/stream-standalone.o: shared/geom.h shared/ents.h shared/iengine.h
shared/stream-standalone.o: shared/igame.h
shared/tools-standalone.o: shared/cube.h shared/tools.h shared/command.h
shared/tools-standalone.o: shared/geom.h shared/ents.h shared/iengine.h
shared/tools-standalone.o: shared/igame.h
engine/command-standalone.o: engine/engine.h shared/cube.h shared/tools.h
engine/command-standalone.o: shared/command.h shared/geom.h shared/ents.h
engine/command-standalone.o: shared/iengine.h shared/igame.h engine/irc.h
engine/command-standalone.o: engine/sound.h
engine/irc-standalone.o: engine/engine.h shared/cube.h shared/tools.h
engine/irc-standalone.o: shared/command.h shared/geom.h shared/ents.h
engine/irc-standalone.o: shared/iengine.h shared/igame.h engine/irc.h
engine/irc-standalone.o: engine/sound.h
engine/master-standalone.o: engine/engine.h shared/cube.h shared/tools.h
engine/master-standalone.o: shared/command.h shared/geom.h shared/ents.h
engine/master-standalone.o: shared/iengine.h shared/igame.h engine/irc.h
engine/master-standalone.o: engine/sound.h
engine/server-standalone.o: engine/engine.h shared/cube.h shared/tools.h
engine/server-standalone.o: shared/command.h shared/geom.h shared/ents.h
engine/server-standalone.o: shared/iengine.h shared/igame.h engine/irc.h
engine/server-standalone.o: engine/sound.h
game/server-standalone.o: game/game.h engine/engine.h shared/cube.h
game/server-standalone.o: shared/tools.h shared/command.h shared/geom.h
game/server-standalone.o: shared/ents.h shared/iengine.h shared/igame.h
game/server-standalone.o: engine/irc.h engine/sound.h game/weapons.h
game/server-standalone.o: game/gamemode.h game/team.h game/ai.h game/vars.h
game/server-standalone.o: game/capture.h game/defend.h game/bomber.h
game/server-standalone.o: game/auth.h game/capturemode.h game/defendmode.h
game/server-standalone.o: game/bombermode.h game/duelmut.h game/aiman.h
game/server-standalone.o: game/extinfo.h
game/punitiveeffects-standalone.o: game/punitiveeffects.cpp game/game.h

shared/cube.h.gch: shared/tools.h shared/command.h shared/geom.h
shared/cube.h.gch: shared/ents.h shared/iengine.h shared/igame.h
engine/engine.h.gch: shared/cube.h shared/tools.h shared/command.h
engine/engine.h.gch: shared/geom.h shared/ents.h shared/iengine.h
engine/engine.h.gch: shared/igame.h engine/irc.h engine/sound.h
engine/engine.h.gch: engine/world.h engine/octa.h engine/lightmap.h
engine/engine.h.gch: engine/bih.h engine/texture.h engine/model.h
engine/engine.h.gch: engine/varray.h

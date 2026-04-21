# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
from .models import Project, Binary, Snapshot
from .packets import (
    Command,
    Container,
    DefaultCommand,
    ParentCommand,
    Query as IQuery,
    Reply as IReply,
)


class ListProjects(ParentCommand):
    __command__ = "list_projects"

    class Query(IQuery, DefaultCommand):
        pass

    class Reply(IReply, Command):
        def __init__(self, query, projects):
            super(ListProjects.Reply, self).__init__(query)
            self.projects = projects

        def build_command(self, dct):
            dct["projects"] = [project.build({}) for project in self.projects]

        def parse_command(self, dct):
            self.projects = [Project.new(project) for project in dct["projects"]]


class ListBinaries(ParentCommand):
    __command__ = "list_binaries"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project):
            super(ListBinaries.Query, self).__init__()
            self.project = project

    class Reply(IReply, Command):
        def __init__(self, query, binaries):
            super(ListBinaries.Reply, self).__init__(query)
            self.binaries = binaries

        def build_command(self, dct):
            dct["binaries"] = [binary.build({}) for binary in self.binaries]

        def parse_command(self, dct):
            self.binaries = [Binary.new(binary) for binary in dct["binaries"]]


class ListSnapshots(ParentCommand):
    __command__ = "list_snapshots"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project, binary):
            super(ListSnapshots.Query, self).__init__()
            self.project = project
            self.binary = binary

    class Reply(IReply, Command):
        def __init__(self, query, snapshots):
            super(ListSnapshots.Reply, self).__init__(query)
            self.snapshots = snapshots

        def build_command(self, dct):
            dct["snapshots"] = [snapshot.build({}) for snapshot in self.snapshots]

        def parse_command(self, dct):
            self.snapshots = [Snapshot.new(snapshot) for snapshot in dct["snapshots"]]


class CreateProject(ParentCommand):
    __command__ = "create_project"

    class Query(IQuery, Command):
        def __init__(self, project):
            super(CreateProject.Query, self).__init__()
            self.project = project

        def build_command(self, dct):
            self.project.build(dct["project"])

        def parse_command(self, dct):
            self.project = Project.new(dct["project"])

    class Reply(IReply, Command):
        pass


class DeleteProject(ParentCommand):
    __command__ = "delete_project"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project):
            super(DeleteProject.Query, self).__init__()
            self.project = project

    class Reply(IReply, DefaultCommand):
        def __init__(self, query, deleted):
            super(DeleteProject.Reply, self).__init__(query)
            self.deleted = deleted


class CreateBinary(ParentCommand):
    __command__ = "create_binary"

    class Query(IQuery, Command):
        def __init__(self, binary):
            super(CreateBinary.Query, self).__init__()
            self.binary = binary

        def build_command(self, dct):
            self.binary.build(dct["binary"])

        def parse_command(self, dct):
            self.binary = Binary.new(dct["binary"])

    class Reply(IReply, Command):
        pass


class DeleteBinary(ParentCommand):
    __command__ = "delete_binary"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project, binary):
            super(DeleteBinary.Query, self).__init__()
            self.project = project
            self.binary = binary

    class Reply(IReply, DefaultCommand):
        def __init__(self, query, deleted):
            super(DeleteBinary.Reply, self).__init__(query)
            self.deleted = deleted


class CreateSnapshot(ParentCommand):
    __command__ = "create_snapshot"

    class Query(IQuery, Command):
        def __init__(self, snapshot):
            super(CreateSnapshot.Query, self).__init__()
            self.snapshot = snapshot

        def build_command(self, dct):
            self.snapshot.build(dct["snapshot"])

        def parse_command(self, dct):
            self.snapshot = Snapshot.new(dct["snapshot"])

    class Reply(IReply, Command):
        pass


class DeleteSnapshot(ParentCommand):
    __command__ = "delete_snapshot"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project, binary, snapshot):
            super(DeleteSnapshot.Query, self).__init__()
            self.project = project
            self.binary = binary
            self.snapshot = snapshot

    class Reply(IReply, DefaultCommand):
        def __init__(self, query, deleted):
            super(DeleteSnapshot.Reply, self).__init__(query)
            self.deleted = deleted


class UpdateFile(ParentCommand):
    __command__ = "update_file"

    class Query(IQuery, Container, DefaultCommand):
        def __init__(self, project, binary, snapshot):
            super(UpdateFile.Query, self).__init__()
            self.project = project
            self.binary = binary
            self.snapshot = snapshot

    class Reply(IReply, Command):
        pass


class DownloadFile(ParentCommand):
    __command__ = "download_file"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project, binary, snapshot):
            super(DownloadFile.Query, self).__init__()
            self.project = project
            self.binary = binary
            self.snapshot = snapshot

    class Reply(IReply, Container, Command):
        pass


class RenameBinary(ParentCommand):
    __command__ = "rename_binary"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project, old_name, new_name):
            super(RenameBinary.Query, self).__init__()
            self.project = project
            self.old_name = old_name
            self.new_name = new_name

    class Reply(IReply, Command):
        def __init__(self, query, binaries, renamed):
            super(RenameBinary.Reply, self).__init__(query)
            self.binaries = binaries
            self.renamed = renamed

        def build_command(self, dct):
            dct["renamed"] = self.renamed
            dct["binaries"] = [binary.build({}) for binary in self.binaries]

        def parse_command(self, dct):
            self.renamed = dct["renamed"]
            self.binaries = [Binary.new(binary) for binary in dct["binaries"]]


class JoinSession(DefaultCommand):
    __command__ = "join_session"

    def __init__(self, project, binary, snapshot, tick, name, color, ea, silent=True):
        super(JoinSession, self).__init__()
        self.project = project
        self.binary = binary
        self.snapshot = snapshot
        self.tick = tick
        self.name = name
        self.color = color
        self.ea = ea
        self.silent = silent


class LeaveSession(DefaultCommand):
    __command__ = "leave_session"

    def __init__(self, name, silent=True):
        super(LeaveSession, self).__init__()
        self.name = name
        self.silent = silent


class UpdateUserName(DefaultCommand):
    __command__ = "update_user_name"

    def __init__(self, old_name, new_name):
        super(UpdateUserName, self).__init__()
        self.old_name = old_name
        self.new_name = new_name


class UpdateUserColor(DefaultCommand):
    __command__ = "update_user_color"

    def __init__(self, name, old_color, new_color):
        super(UpdateUserColor, self).__init__()
        self.name = name
        self.old_color = old_color
        self.new_color = new_color


class UpdateLocation(DefaultCommand):
    __command__ = "update_location"

    def __init__(self, name, ea, color):
        super(UpdateLocation, self).__init__()
        self.name = name
        self.ea = ea
        self.color = color


class InviteToLocation(DefaultCommand):
    __command__ = "invite_to_location"

    def __init__(self, name, loc):
        super(InviteToLocation, self).__init__()
        self.name = name
        self.loc = loc

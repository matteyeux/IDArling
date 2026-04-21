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
import json
import sqlite3

from .models import Project, Binary, Snapshot
from .packets import Default, DefaultEvent


class Storage(object):
    """
    This object is used to access the SQL database used by the server. It
    also defines some utility methods. Currently, only SQLite3 is implemented.
    """

    def __init__(self, dbpath):
        self._conn = sqlite3.connect(dbpath, check_same_thread=False)
        self._conn.isolation_level = None  # No need to commit
        self._conn.row_factory = sqlite3.Row  # Use Row objects

    def initialize(self):
        """Create all the default tables."""
        self._create(
            "projects",
            [
                "name text not null",
                "date text not null",
                "primary key (name)",
            ],
        )
        self._create(
            "binaries",
            [
                "project text not null",
                "name text not null",
                "hash text not null",
                "file text not null",
                "type text not null",
                "date text not null",
                "foreign key(project) references projects(name)",
                "primary key (project, name)",
            ],
        )
        self._create(
            "snapshots",
            [
                "project text not null",
                "binary text not null",
                "name text not null",
                "date text not null",
                "foreign key(project) references projects(name)",
                "foreign key(project, binary) references binaries(project, name)",
                "primary key(project, binary, name)",
            ],
        )
        self._create(
            "events",
            [
                "project text not null",
                "binary text not null",
                "snapshot text not null",
                "tick integer not null",
                "dict text not null",
                "foreign key(project) references projects(name)",
                "foreign key(project, binary) references binaries(project, name)",
                "foreign key(project, binary, snapshot)"
                "     references snapshots(project, binary, name)",
                "primary key(project, binary, snapshot, tick)",
            ],
        )

    def insert_project(self, project):
        """Insert a new project into the database."""
        self._insert("projects", Default.attrs(project.__dict__))

    def select_project(self, name):
        """Select the project with the given name."""
        objects = self.select_projects(name, 1)
        return objects[0] if objects else None

    def select_projects(self, name=None, limit=None):
        """Select the projects with the given name."""
        results = self._select("projects", {"name": name}, limit)
        return [Project(**result) for result in results]

    def insert_binary(self, binary):
        """Insert a new binary into the database."""
        self._insert("binaries", Default.attrs(binary.__dict__))

    def select_binary(self, name):
        """Select the binary with the given name."""
        objects = self.select_binaries(name, 1)
        return objects[0] if objects else None

    def select_binaries(self, project=None, name=None, limit=None):
        """Select the binaries with the given project and name."""
        results = self._select("binaries", {"project": project, "name": name}, limit)
        return [Binary(**result) for result in results]

    def update_binary_name(
        self, project=None, old_name=None, new_name=None, limit=None
    ):
        """Update a binary with the given new name."""
        self._update(
            "binaries", "name", new_name, {"project": project, "name": old_name}, limit
        )

    def update_snapshot_binary(
        self, project=None, old_name=None, new_name=None, limit=None
    ):
        """Update a binary with the given new name."""
        self._update(
            "snapshots",
            "binary",
            new_name,
            {"project": project, "binary": old_name},
            limit,
        )

    def update_events_binary(
        self, project=None, old_name=None, new_name=None, limit=None
    ):
        """Update a binary with the given new name."""
        self._update(
            "events",
            "binary",
            new_name,
            {"project": project, "binary": old_name},
            limit,
        )

    def insert_snapshot(self, snapshot):
        """Insert a new snapshot into the database."""
        attrs = Default.attrs(snapshot.__dict__)
        attrs.pop("tick")
        self._insert("snapshots", attrs)

    def select_snapshot(self, project, binary, name):
        """Select the snapshot with the given binary and name."""
        objects = self.select_snapshots(project, binary, name, 1)
        return objects[0] if objects else None

    def select_snapshots(self, project=None, binary=None, name=None, limit=None):
        """Select the snapshots with the given binary and name."""
        results = self._select(
            "snapshots", {"project": project, "binary": binary, "name": name}, limit
        )
        return [Snapshot(**result) for result in results]

    def insert_event(self, client, event):
        """Insert a new event into the database."""
        dct = DefaultEvent.attrs(event.__dict__)
        self._insert(
            "events",
            {
                "project": client.project,
                "binary": client.binary,
                "snapshot": client.snapshot,
                "tick": event.tick,
                "dict": json.dumps(dct),
            },
        )

    def select_events(self, project, binary, snapshot, tick):
        """Get all events sent after the given tick count."""
        c = self._conn.cursor()
        sql = "select * from events where project = ? and binary = ? and snapshot = ?"
        sql += "and tick > ? order by tick asc;"
        c.execute(sql, [project, binary, snapshot, tick])
        events = []
        for result in c.fetchall():
            dct = json.loads(result["dict"])
            dct["tick"] = result["tick"]
            events.append(DefaultEvent.new(dct))
        return events

    def last_tick(self, project, binary, snapshot):
        """Get the last tick of the specified binary and snapshot."""
        c = self._conn.cursor()
        sql = (
            "select tick from events where project = ? and binary = ? and snapshot = ? "
        )
        sql += "order by tick desc limit 1;"
        c.execute(sql, [project, binary, snapshot])
        result = c.fetchone()
        return result["tick"] if result else 0

    def delete_events(self, project, binary, snapshot):
        self._delete(
            "events", {"project": project, "binary": binary, "snapshot": snapshot}
        )

    def delete_snapshot(self, project, binary, snapshot):
        self.delete_events(project, binary, snapshot)
        self._delete(
            "snapshots", {"project": project, "binary": binary, "name": snapshot}
        )

    def delete_binary(self, project, binary):
        self._delete("events", {"project": project, "binary": binary})
        self._delete("snapshots", {"project": project, "binary": binary})
        self._delete("binaries", {"project": project, "name": binary})

    def delete_project(self, project):
        self._delete("events", {"project": project})
        self._delete("snapshots", {"project": project})
        self._delete("binaries", {"project": project})
        self._delete("projects", {"name": project})

    def _create(self, table, cols):
        """Create a table with the given name and columns."""
        c = self._conn.cursor()
        sql = "create table if not exists {} ({});"
        c.execute(sql.format(table, ", ".join(cols)))

    def _select_all(self, table):
        """Select all the rows of a table."""
        c = self._conn.cursor()
        sql = "select * from {}".format(table)
        c.execute(sql)
        return [dict(row) for row in c.fetchall()]

    def _select(self, table, fields, limit=None):
        """Select the rows of a table matching the given values."""
        c = self._conn.cursor()
        sql = "select * from {}".format(table)
        fields = {key: val for key, val in fields.items() if val}
        if len(fields):
            cols = ["{} = ?".format(col) for col in fields.keys()]
            sql = (sql + " where {}").format(" and ".join(cols))
        sql += " limit {};".format(limit) if limit else ";"
        c.execute(sql, list(fields.values()))
        return c.fetchall()

    def _delete(self, table, fields):
        """Delete the rows of a table matching the given values."""
        c = self._conn.cursor()
        sql = "delete from {}".format(table)
        fields = {key: val for key, val in fields.items() if val}
        if len(fields):
            cols = ["{} = ?".format(col) for col in fields.keys()]
            sql = (sql + " where {}").format(" and ".join(cols))
        sql += ";"
        c.execute(sql, list(fields.values()))

    def _update(self, table, field, new_value, search_fields, limit=None):
        """Update the field in a table matching the given search fields."""
        c = self._conn.cursor()
        sql = "update {} set {} = ?".format(table, field)
        search_fields = {key: val for key, val in search_fields.items() if val}
        if len(search_fields):
            cols = ["{} = ?".format(col) for col in search_fields.keys()]
            sql = (sql + " where {}").format(" and ".join(cols))
        sql += " limit {};".format(limit) if limit else ";"
        conditions = [new_value] + list(search_fields.values())
        # print(sql)
        # print(conditions)
        c.execute(sql, conditions)
        return c.fetchall()

    def _insert_all(self, table, rows):
        for fields in rows:
            self._insert(table, fields)

    def _insert(self, table, fields):
        """Insert a row into a table with the given values."""
        c = self._conn.cursor()
        sql = "insert into {} ({}) values ({});"
        keys = ", ".join(fields.keys())
        vals = ", ".join(["?"] * len(fields))
        c.execute(sql.format(table, keys, vals), list(fields.values()))

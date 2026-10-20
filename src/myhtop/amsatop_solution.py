import os
from typing import List

from amsatop import Htop, Process, TaskType
from amsatop.utils import StatFile, get_stat_file_from_path, get_status_file_from_path

PF_KTHREAD = 0x00200000
SIGHUP = 1


class Amsatop(Htop):
    def __init__(self):
        super().__init__()

    def read_stat(self, task_dir: str) -> StatFile | None:
        try:
            return get_stat_file_from_path(os.path.join(task_dir, "stat"))
        except (ValueError, OSError):
            return None

    def is_kernel_thread(self, stat):
        return (stat.flags & PF_KTHREAD) != 0

    def get_threads(self, pid_folder, pid):
        threads = []
        task_folder = os.path.join(pid_folder, "task")
        try:
            names = os.listdir(task_folder)
        except OSError:
            return threads

        for name in names:
            if name.isdigit() and name != pid:
                folder = os.path.join(task_folder, name)
                stat = self.read_stat(folder)
                if stat is not None:
                    threads.append((folder, TaskType.THREAD, stat))
        return threads

    def get_tasks(self):
        tasks = []
        for name in os.listdir(self.proc_folder):
            if not name.isdigit():
                continue

            folder = os.path.join(self.proc_folder, name)
            stat = self.read_stat(folder)
            if stat is None:
                continue

            if self.is_kernel_thread(stat):
                tasks.append((folder, TaskType.KTHREAD, stat))
            else:
                tasks.append((folder, TaskType.PROCESS, stat))
                tasks.extend(self.get_threads(folder, name))
        return tasks

    def get_processes(self) -> List[Process]:
        return [
            Process(stat.pid, stat.command, task_type, None)
            for folder, task_type, stat in self.get_tasks()
        ]

    def get_priorities(self) -> List[Process]:
        return [
            Process(stat.pid, stat.command, task_type, stat.priority)
            for folder, task_type, stat in self.get_tasks()
        ]

    def get_hup(self) -> List[Process]:
        mask = 1 << (SIGHUP - 1)
        processes = []
        for task_dir, task_type, stat in self.get_tasks():
            status = get_status_file_from_path(os.path.join(task_dir, "status"))
            if status is None: 
                continue
            if int(status.SigIgn or "0", 16) & mask:
                processes.append(Process(stat.pid, stat.command, task_type, stat.priority))
        return processes
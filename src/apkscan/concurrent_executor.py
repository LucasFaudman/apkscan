# © 2023 Lucas Faudman.
# Licensed under the MIT License (see LICENSE for details).
# For commercial use, see LICENSE for additional terms.
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed, Future
from typing import Callable, Iterable, Iterator, Generator, Literal, Optional, TypeVar

T = TypeVar("T")

# Defined outside of class to allow for standalone use
def execute_concurrently(
    func: Callable[..., T],
    *iterables: Iterable,
    concurrency_type: Optional[Literal["thread", "process", "main", False]] = "thread",
    results_order: Literal["completed", "submitted"] = "completed",
    max_workers: Optional[int] = None,
    chunksize: int = 1,
    timeout: Optional[int] = None,
    shutdown: bool = True,
    wait: bool = True,
    cancel_pending: bool = False,
    executor: Optional[ThreadPoolExecutor | ProcessPoolExecutor] = None,
    **executor_init_kwargs,
) -> Generator[T, None, Optional[ThreadPoolExecutor | ProcessPoolExecutor]]:
    """Execute function concurrently with arguments from iterables.

    Args:
        func: Function to execute concurrently that takes as many arguments as there are iterables.
        *iterables: Iterables of args to pass to function calls in parallel e.g. ([call0_arg0, call1_arg0], [call0_arg1, call1_arg1], ...)
        concurrency_type: Concurrency type used to execute function. (Multithreading, Multiprocessing, or Main/Single Thread) Defaults to "thread".
        results_order: Order to yield results. Either in order completed or order submitted. Defaults to "completed".
        max_workers: Maximum number of threads or processes to use. Defaults to None (number of CPUs).
        chunksize: The size of the chunks the iterable will be broken into before being passed to a child process. Only used when concurrency_type is "process". Defaults to 1.
        timeout: The maximum number of seconds to wait. If None, then there is no limit on the wait time.
        shutdown: Whether to shutdown executor after completion or to return it for reuse. Defaults to True. If False, returns executor instance on StopIteration.
        wait: Whether to wait for executor to shutdown. Defaults to True.
        cancel_pending: Whether to cancel pending futures on shutdown. Defaults to False.
        executor: Reuse an existing ThreadPoolExecutor or ProcessPoolExecutor instance. Defaults to None.
        executor_init_kwargs: Additional keyword arguments to pass to ThreadPoolExecutor or ProcessPoolExecutor constructor. Defaults to None.

    Yields:
        Results from function execution with arguments from iterables in order of completion or submission.
    """

    # Single-threaded execution in main thread (concurrency_type = "main"|False|None)
    if not concurrency_type or concurrency_type == "main":
        for args in zip(*iterables):
            yield func(*args)
        return

    # Multi-threaded or multi-process execution (concurrency_type = "thread"|"process")
    if not executor:
        executor_cls = ProcessPoolExecutor if "proc" in concurrency_type else ThreadPoolExecutor
        executor = executor_cls(max_workers=max_workers, **executor_init_kwargs)

    if "submit" in results_order:
        # Yield results in order of submission
        yield from executor.map(func, *iterables, timeout=timeout, chunksize=chunksize)
    else:
        # Yield results in order of completion
        futures_generator = (executor.submit(func, *args) for args in zip(*iterables))
        yield from map(Future.result, as_completed(futures_generator, timeout=timeout))

    # Shutdown executor or return it on StopIteration to be reused
    if shutdown:
        return executor.shutdown(wait=wait, cancel_futures=cancel_pending)
    else:
        return executor


class ConcurrentExecutor:
    def __init__(
        self,
        concurrency_type: Optional[Literal["thread", "process", "main", False]] = "thread",
        results_order: Literal["completed", "submitted"] = "completed",
        max_workers: Optional[int] = None,
        chunksize: int = 1,
        timeout: Optional[int] = None,
        shutdown: bool = True,
        wait: bool = True,
        cancel_pending: bool = False,
        executor: Optional[ThreadPoolExecutor | ProcessPoolExecutor] = None,
        **executor_init_kwargs,
    ) -> None:
        self.concurrency_type = concurrency_type
        self.results_order = results_order
        self.max_workers = max_workers
        self.chunksize = chunksize
        self.timeout = timeout
        self._shutdown = shutdown
        self.wait = wait
        self.cancel_pending = cancel_pending
        self.executor = executor
        self.executor_init_kwargs = executor_init_kwargs

    def map(self, func: Callable[..., T], *iterables: Iterable, **kwargs) -> Iterator[T]:
        self.executor = yield from execute_concurrently(
            func,
            *iterables,
            **{
                "concurrency_type": self.concurrency_type,
                "results_order": self.results_order,
                "max_workers": self.max_workers,
                "chunksize": self.chunksize,
                "shutdown": self._shutdown,
                "timeout": self.timeout,
                "wait": self.wait,
                "cancel_pending": self.cancel_pending,
                "executor": self.executor,
                **self.executor_init_kwargs,
                **kwargs,
            },
        )

    def shutdown(self, wait: Optional[bool] = None, cancel_pending: Optional[bool] = None) -> None:
        if self.executor:
            self.executor.shutdown(
                wait=wait if wait is not None else self.wait,
                cancel_futures=cancel_pending if cancel_pending is not None else self.cancel_pending
            )
            self.executor = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def __del__(self):
        self.shutdown()

    def __repr__(self) -> str:
        return f"CuncurrentExecutor(concurrency_type={self.concurrency_type}, results_order={self.results_order}, max_workers={self.max_workers}, chunksize={self.chunksize}, timeout={self.timeout}, shutdown={self._shutdown}, wait={self.wait}, cancel_pending={self.cancel_pending}, executor={self.executor}, executor_init_kwargs={self.executor_init_kwargs})"

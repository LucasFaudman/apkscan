from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed, Future
from typing import Any, Callable, Iterable, Generator, Literal, Optional, TypeAlias

ConcurrencyType: TypeAlias = Literal["thread", "process", "main", False]
ResultsOrder: TypeAlias = Literal["completed", "submitted"]
OptionalExecutor: TypeAlias = Optional[ThreadPoolExecutor|ProcessPoolExecutor]

# Defined outside of class to allow for standalone use
def execute_concurrently(func: Callable, 
                         *iterables: Iterable, 
                         concurrency_type: Optional[Literal["thread", "process", "main", False]] = "thread",
                         results_order: Literal["completed", "submitted"] = "completed",
                         max_workers: Optional[int] = None,
                         shutdown: bool = True,
                         executor_instance: Optional[ThreadPoolExecutor|ProcessPoolExecutor] = None
                         ) -> Generator[Any, None, Optional[ThreadPoolExecutor|ProcessPoolExecutor]]:
    
    """Execute function concurrently with arguments from iterables.

    Args:
        func: Function to execute concurrently
        *iterables: Iterables of args to pass to function calls in parallel e.g. ([call0_arg0, call1_arg0], [call0_arg1, call1_arg1], ...)
        concurrency_type: Concurrency type used to execute function. (Multithreading, Multiprocessing, or Main/Single Thread) Defaults to "thread".
        results_order: Order to yield results. Either in order completed or order submitted. Defaults to "completed".
        max_workers: Maximum number of threads or processes to use. Defaults to None (number of CPUs).

    Yields:
        Results from function execution with arguments from iterables in order of completion or submission.
    """

    # Single-threaded execution in main thread (concurrency_type = "main"|False|None)
    if not concurrency_type or concurrency_type == 'main':
        for args in zip(*iterables):
            yield func(*args)
        return
    
    # Multi-threaded or multi-process execution (concurrency_type = "thread"|"process")
    if executor_instance:
        executor = executor_instance
    elif 'proc' in concurrency_type: 
        executor = ProcessPoolExecutor(max_workers=max_workers)
    else:
        executor = ThreadPoolExecutor(max_workers=max_workers)

    if 'submit' in results_order:
        # Yield results in order of submission
        yield from executor.map(func, *iterables)
    else:
        # Yield results in order of completion
        for future in as_completed(executor.submit(func, *args) for args in zip(*iterables)):
            yield future.result()
    
    # Shutdown executor or return it on StopIteration to be reused
    if shutdown:
        return executor.shutdown(wait=True)
    else:
        return executor


class ConcurrentExecutor:
    def __init__(self, 
                 concurrency_type: Optional[Literal["thread", "process", "main", False]] = "thread",
                 results_order: Literal["completed", "submitted"] = "completed",
                 max_workers: Optional[int] = None,
                 shutdown: bool = False,
                 executor_instance: Optional[ThreadPoolExecutor|ProcessPoolExecutor] = None
                 ):
        self.concurrency_type = concurrency_type
        self.results_order = results_order
        self.max_workers = max_workers
        self.shutdown = shutdown
        self.executor = executor_instance

    def map(self, func: Callable, *iterables: Iterable) -> Generator[Any, None, None]:
        self.executor = yield from execute_concurrently(
            func, *iterables, 
            concurrency_type=self.concurrency_type, # type: ignore
            results_order=self.results_order, # type: ignore
            max_workers=self.max_workers,
            shutdown=self.shutdown,
            executor_instance=self.executor)
        
    def __del__(self):
        if self.executor:
            self.executor.shutdown(wait=True)
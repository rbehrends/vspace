#include "vspace.h"

using namespace vspace;

const int nqueens = 14;
const int nworkers = 8;

pid_t workers[nworkers];
enum TaskType {
  CheckBoard,
  Terminate,
};

struct Task {
  TaskType type;
  int a, b;
  Task(TaskType type, int a = 0, int b = 0) : type(type), a(a), b(b) {}
};

struct Board {
  bool squares[nqueens][nqueens];
  bool legal_move(int row, int col) {
    for (int i = 0; i < row; i++) {
      if (squares[i][col])
        return false;
      if (col-i-1 >= 0 && squares[row-i-1][col-i-1])
        return false;
      if (col+i+1 < nqueens && squares[row-i-1][col+i+1])
        return false;
    }
    return true;
  }
  int count_solutions(int row) {
    int result = 0;
    for (int col = 0; col < nqueens; col++) {
      if (legal_move(row, col)) {
        if (row == nqueens-1)
          result++;
        else {
          squares[row][col] = true;
          result += count_solutions(row+1);
          squares[row][col] = false;
        }
      }
    }
    return result;
  }
};

VRef<Queue<Task> > task_queue;
VRef<Queue<int> > result_queue;

void worker() {
  for (;;) {
    VRef<Task> msg = task_queue->dequeue();
    Task task = *msg;
    msg.free();
    if (task.type == Terminate) {
      result_queue->enqueue(vnew<int>(-1));
      exit(0);
    }
    Board board = Board();
    board.squares[0][task.a] = true;
    board.squares[1][task.b] = true;
    int solutions = board.count_solutions(2);
    result_queue->enqueue(vnew<int>(solutions));
  }
}

int main() {
  vmem_init();
  task_queue = vnew<Queue<Task> >();
  result_queue = vnew<Queue<int> >();
  for (int i = 0; i < nworkers; i++) {
    pid_t pid = fork_process();
    if (pid == 0) {
      worker();
    } else if (pid > 0) {
      workers[i] = pid;
    } else {
      perror("fork");
      abort();
    }
  }
  for (int i = 0; i < nqueens; i++) {
    for (int j = 0; j < nqueens; j++) {
      if (abs(i-j) >= 2)
        task_queue->enqueue(vnew<Task>(CheckBoard, i, j));
    }
  }
  for (int i = 0; i < nworkers; i++) {
    task_queue->enqueue(vnew<Task>(Terminate));
  }
  int result = 0;
  for (int i = 0; i < nworkers; i++) {
    for (;;) {
      VRef<int> msg = result_queue->dequeue();
      int d = *msg;
      msg.free();
      if (d < 0)
        break;
      result += d;
    }
  }
  printf("%d\n", result);
  fflush(stdout);
  for (int i = 0; i < nworkers; i++)
    waitpid(workers[i], NULL, 0);
}
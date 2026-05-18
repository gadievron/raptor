#include <iostream>

class Widget {
public:
    void setup();
    int run(int x);
    ~Widget();
private:
    int counter_;
};

void Widget::setup() {
    counter_ = 0;
    helper();
}

int Widget::run(int x) {
    this->setup();
    if (x > 0) {
        return x * 2;
    }
    return 0;
}

Widget::~Widget() {
    cleanup();
}

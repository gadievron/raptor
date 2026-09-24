"""Views referenced by the urlconf fixture."""


def login_required(f):
    return f


@login_required
def detail(pk):
    return pk


def archive(year):
    return year


class ItemView:
    def get(self, request):
        return "get"

    def post(self, request):
        return "post"

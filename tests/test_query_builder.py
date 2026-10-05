import pytest
from sqlalchemy.dialects import mysql

from cpm_server.data.query_builder import FilterCondition, OrderBy, build_count, build_select
from cpm_server.data.source import ColumnInfo, TableInfo
from cpm_server.errors import QueryValidationError
from cpm_server.security.policy import AccessPolicy

POLICY = AccessPolicy(["sessions"], ["password", "*_token"])


def col(name, key=""):
    return ColumnInfo(name=name, data_type="text", column_type="text", nullable=True, key=key, comment="")


USERS = TableInfo(
    name="users",
    kind="BASE TABLE",
    row_estimate=None,
    comment="",
    columns=(col("id", "PRI"), col("name"), col("email"), col("password"), col("api_token")),
)


def build(**kw):
    args = dict(columns=None, filters=None, order_by=None, limit=10, offset=0, max_rows=100)
    args.update(kw)
    return build_select(USERS, POLICY, **args)


def sql(built):
    compiled = built.statement.compile(dialect=mysql.dialect())
    return str(compiled), compiled.params


def test_hidden_columns_are_never_selected_by_default():
    built = build()
    assert built.columns == ["id", "name", "email"]
    text, _ = sql(built)
    assert "password" not in text and "api_token" not in text


@pytest.mark.parametrize("name", ["password", "api_token", "nope"])
def test_hidden_and_unknown_columns_are_rejected_everywhere(name):
    with pytest.raises(QueryValidationError):
        build(columns=[name])
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column=name, op="like", value="a%")])
    with pytest.raises(QueryValidationError):
        build(order_by=[OrderBy(column=name)])
    with pytest.raises(QueryValidationError):
        build_count(USERS, POLICY, filters=[FilterCondition(column=name, value="x")])


def test_identifier_injection_is_rejected_by_the_whitelist():
    for evil in ["id; DROP TABLE users", "id`, (SELECT password FROM users) --", "id) OR (1=1", "*"]:
        with pytest.raises(QueryValidationError):
            build(columns=[evil])
        with pytest.raises(QueryValidationError):
            build(filters=[FilterCondition(column=evil, value=1)])
        with pytest.raises(QueryValidationError):
            build(order_by=[OrderBy(column=evil)])


def test_values_are_bound_never_inlined():
    evil = "x' OR '1'='1"
    text, params = sql(build(filters=[FilterCondition(column="name", op="=", value=evil)]))
    assert evil not in text
    assert evil in params.values()


def test_like_value_is_bound():
    text, params = sql(build(filters=[FilterCondition(column="name", op="like", value="A%'; --")]))
    assert "A%" not in text
    assert "A%'; --" in params.values()


def test_limit_is_capped_and_one_extra_row_is_requested():
    built = build(limit=10_000, max_rows=100)
    assert built.limit == 100
    text, params = sql(built)
    assert 101 in params.values()
    assert build(limit=0).limit == 1


def test_offset_bounds():
    with pytest.raises(QueryValidationError):
        build(offset=-1)
    with pytest.raises(QueryValidationError):
        build(offset=10_000_000)


def test_default_order_is_primary_key_for_stable_paging():
    text, _ = sql(build())
    assert "ORDER BY `id` ASC" in text


def test_identifiers_are_always_quoted():
    text, _ = sql(build())
    assert "FROM `users`" in text


def test_operator_validation():
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column="id", op="in", value=5)])
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column="id", op="in", value=[])])
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column="id", op="=", value=None)])
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column="id", op="=", value=[1, 2])])
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column="id", op="in", value=list(range(201)))])
    with pytest.raises(QueryValidationError):
        build(filters=[FilterCondition(column="name", op="like", value="a" * 500)])


def test_is_null_variants():
    t1, _ = sql(build(filters=[FilterCondition(column="email", op="is_null")]))
    t2, _ = sql(build(filters=[FilterCondition(column="email", op="is_null", value=True)]))
    t3, _ = sql(build(filters=[FilterCondition(column="email", op="is_null", value=False)]))
    assert "`email` IS NULL" in t1 and "`email` IS NULL" in t2
    assert "`email` IS NOT NULL" in t3


def test_filter_count_limit():
    flts = [FilterCondition(column="id", value=i) for i in range(21)]
    with pytest.raises(QueryValidationError):
        build(filters=flts)


def test_table_without_visible_columns():
    only_hidden = TableInfo("t", "BASE TABLE", None, "", (col("password"),))
    with pytest.raises(QueryValidationError):
        build_select(only_hidden, POLICY, columns=None, filters=None, order_by=None, limit=1, offset=0, max_rows=10)

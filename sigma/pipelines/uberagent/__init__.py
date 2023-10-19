from .uberagent import uberagent, uberagent600, uberagent610, uberagent620, uberagent700, uberagent710, \
    uberagent_develop

pipelines = {
    "uberagent": uberagent,
    "uberagent-6.0.0": uberagent600,
    "uberagent-6.1.0": uberagent610,
    "uberagent-6.2.0": uberagent620,
    "uberagent-7.0.0": uberagent700,
    "uberagent-7.1.0": uberagent710,
    "uberagent-develop": uberagent_develop,
}

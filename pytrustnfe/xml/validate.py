# -*- coding: utf-8 -*-
# © 2016 Alessandro Fernandes Martini <alessandrofmartini@gmail.com>, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import os

from lxml import etree

PATH = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(PATH, "schemas/enviNFe_v4.00.xsd")
SCHEMA_DFE = os.path.join(PATH, "schemas/distDFeInt_v1.01.xsd")
SCHEMA_MDFE = os.path.join(PATH, "schemas/enviMDFe_v3.00.xsd")
#SCHEMA_MDFE_DFE = os.path.join(PATH, "schemas/distDFeInt_v1.01.xsd")


def valida_nfe(xml_nfe, schema=SCHEMA):
    nfe = etree.fromstring(xml_nfe)
    esquema = etree.XMLSchema(etree.parse(schema))
    esquema.validate(nfe)
    erros = [x.message for x in esquema.error_log]
    return "\n".join(erros)

def valida_mdfe(xml_mdfe, schema=SCHEMA_MDFE):
    mdfe = etree.fromstring(xml_mdfe)
    esquema = etree.XMLSchema(etree.parse(schema))
    esquema.validate(mdfe)
    erros = [x.message for x in esquema.error_log]
    return "\n".join(erros)

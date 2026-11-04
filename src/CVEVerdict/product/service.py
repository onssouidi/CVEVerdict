from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from CVEVerdict.matching.matcher import Component
from CVEVerdict.result import FailureKind, Result, fail, ok


@dataclass(slots=True)
class ProductProfile:
    id: str
    name: str
    description: Optional[str] = None
    components: list[Component] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ProductService:
    """Manages product profiles and component inventories."""

    def __init__(self) -> None:
        self._products: dict[str, ProductProfile] = {}

    def create_product(self, name: str, description: Optional[str] = None) -> Result[ProductProfile]:
        if not name or not name.strip():
            return fail(FailureKind.INVALID_RESPONSE, "Product name cannot be empty.")
        
        product_id = str(uuid.uuid4())
        profile = ProductProfile(
            id=product_id,
            name=name.strip(),
            description=description.strip() if description else None,
        )
        self._products[product_id] = profile
        return ok(profile)

    def get_product(self, product_id: str) -> Optional[ProductProfile]:
        return self._products.get(product_id)

    def add_component(
        self,
        product_id: str,
        name: str,
        version: Optional[str] = None,
        cpe: Optional[str] = None,
        purl: Optional[str] = None,
    ) -> Result[Component]:
        product = self.get_product(product_id)
        if not product:
            return fail(FailureKind.NOT_FOUND, f"Product '{product_id}' not found.")

        if not name or not name.strip():
            return fail(FailureKind.INVALID_RESPONSE, "Component name cannot be empty.")

        component = Component(
            name=name.strip(),
            version=version.strip() if version else None,
            cpe=cpe.strip() if cpe else None,
            purl=purl.strip() if purl else None,
        )
        product.components.append(component)
        return ok(component)